import argparse
import base64
import getpass
import gzip
import hashlib
import http.client
import json
import os
import re
import sys
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

TOKEN_ENV="AZURE_STATIC_WEB_APPS_API_TOKEN"
USER_AGENT="staticsites-swacli-v-client"
API_TIMEOUT=10
BLOB_TIMEOUT=10
POLL_SECONDS=15
POLL_LIMIT_SECONDS=600
PRODUCTION_REGIONS={0:"hk1",3:"am2",15:"eus2",16:"dm1",30:"wus2"}
CANARY_REGIONS={33:"euapbn1",34:"euapdm1"}
BETA_REGIONS={21:"msftinthk1",26:"msftinthk1"}

class UploadError(Exception):
	def __init__(self, message, retryable=False):
		super().__init__(message)
		self.retryable=retryable

@dataclass(frozen=True)
class SiteFile:
	path:Path
	relative:str
	archive_name:str
	size:int
	mtime_ns:int
	md5:str

def value(data, name):
	if not isinstance(data, dict):
		return None
	for key, item in data.items():
		if key.casefold()==name.casefold():
			return item
	return None

def safe_message(message, token):
	text=str(message).replace(token, "[redacted token]") if token else str(message)
	text=re.sub(r"https?://[^\s<>\"']+", "[redacted URL]", text, flags=re.IGNORECASE)
	text=re.sub(r"(?i)\bsig=[^&\s]+", "sig=[redacted]", text)
	return text[:800]

def token_endpoint(token):
	if len(token)<104 or "-" not in token:
		raise UploadError("Deployment token has an invalid format.")
	first,second=token.split("-", 1)
	if len(first)<64 or len(second)<39 or not re.fullmatch(r"[0-9a-fA-F]{64}", first[:64]):
		raise UploadError("Deployment token has an invalid format.")
	if len(token)==104:
		raise UploadError("This legacy v0 deployment token needs repository metadata. Create a current deployment token in Azure and try again.")
	if first[64:] and not first[64:].isdecimal():
		raise UploadError("Deployment token has an invalid slice.")
	try:
		uuid.UUID(second[:36])
		region=int(second[36:39], 16)
	except ValueError:
		raise UploadError("Deployment token has an invalid region or site identifier.") from None
	slice_number=int(first[64:] or "0")
	if region in PRODUCTION_REGIONS and slice_number<=8:
		region_name=PRODUCTION_REGIONS[region]
		domain="azurestaticapps.net"
	elif region in CANARY_REGIONS and slice_number<=1:
		region_name=CANARY_REGIONS[region]
		domain="azurestaticappscanary.net"
	elif region in BETA_REGIONS and slice_number==0:
		region_name=BETA_REGIONS[region]
		domain="azurestaticappsbeta.net"
	else:
		raise UploadError("Deployment token selects a region or slice unsupported by this client.")
	suffix="" if slice_number==0 else "."+str(slice_number)
	return "https://content-"+region_name+".infrastructure"+suffix+"."+domain,slice_number

def hash_file(path):
	digest=hashlib.md5()
	with path.open("rb") as source:
		while block:=source.read(1024*1024):
			digest.update(block)
	return digest.hexdigest()

def inventory(folder):
	root=folder.expanduser().resolve()
	if not root.is_dir():
		raise UploadError("Site folder does not exist: "+str(folder))
	if "index.html" not in os.listdir(root) or not (root/"index.html").is_file():
		raise UploadError("The site folder must contain index.html at its root.")
	files=[]
	def walk_error(error):
		raise UploadError("Cannot read the site folder: "+str(error))
	for current, directories, names in os.walk(root, followlinks=False, onerror=walk_error):
		directories[:]=[name for name in directories if name.casefold() not in (".git", ".github")]
		names[:]=[name for name in names if name.casefold() not in (".git", ".github")]
		directories.sort()
		names.sort()
		for name in directories+names:
			entry=Path(current)/name
			if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()) or not entry.resolve().is_relative_to(root):
				raise UploadError("The site folder contains a link or path outside its root: "+str(entry))
		for name in names:
			path=Path(current)/name
			if not path.is_file():
				raise UploadError("The site folder contains an unsupported file: "+str(path))
			before=path.stat()
			relative=os.path.relpath(path, root)
			archive_name=Path(relative).as_posix()
			if archive_name.startswith("/") or ".." in Path(archive_name).parts:
				raise UploadError("Unsafe site path: "+str(path))
			content_hash=hash_file(path)
			after=path.stat()
			if before.st_size!=after.st_size or before.st_mtime_ns!=after.st_mtime_ns:
				raise UploadError("A site file changed during preparation: "+str(path))
			files.append(SiteFile(path, relative, archive_name, after.st_size, after.st_mtime_ns, content_hash))
	return sorted(files, key=lambda item:item.archive_name)

def event_info(slice_number):
	return {"RepoUrl":None,"IsPullRequest":False,"IsNamedEnvironment":False,"PullRequestId":None,"PullRequestTitle":None,"HeadBranch":None,"BaseBranch":None,"EnvironmentName":None,"TenantId":None,"DefaultHostname":None,"Slice":slice_number}

def configured_roles(folder):
	has_config=(folder/"staticwebapp.config.json").is_file()
	has_routes=(folder/"routes.json").is_file() and not has_config
	config_path=folder/("staticwebapp.config.json" if has_config else "routes.json")
	if not has_config and not has_routes:
		return [],False
	try:
		config=json.loads(config_path.read_text(encoding="utf-8-sig"))
	except (OSError, ValueError, UnicodeError) as error:
		raise UploadError("Cannot read "+config_path.name+" as JSON: "+str(error)) from None
	if not isinstance(config, dict) or not isinstance(config.get("routes", []), list):
		raise UploadError(config_path.name+" must contain a JSON object with a routes array.")
	roles=set()
	for rule in config.get("routes", []):
		if not isinstance(rule, dict):
			raise UploadError(config_path.name+" has a malformed route rule.")
		allowed=rule.get("allowedRoles", [])
		if not isinstance(allowed, list) or any(not isinstance(role, str) for role in allowed):
			raise UploadError(config_path.name+" has a malformed allowedRoles list.")
		roles.update(role.lower() for role in allowed if role and role.lower() not in ("anonymous", "authenticated"))
	return sorted(roles),has_routes

def upload_info(folder, files, slice_number):
	roles,has_routes=configured_roles(folder)
	return {"TotalAppSizeInBytes":sum(item.size for item in files),"ApiSizeInBytes":0,"HasFunctions":False,"HasDataApiFiles":False,"HasDataApiConfigFile":False,"DatabaseType":None,"HasRoutes":has_routes,"Status":"RequestingUpload","DefaultFileType":"index.html","ApiContentHash":None,"ConfiguredRoles":roles,"AppFileCount":len(files),"FunctionLanguage":None,"FunctionLanguageVersion":None,"ServerRenderFramework":"StaticWebApp","DeploymentProvider":"SwaCli","MaxSingleFileSizeInBytes":max(item.size for item in files),"BackendStartupCommandType":0,"ShouldDeployToWebApp":False,"TenantId":None,"DefaultHostname":None,"Slice":slice_number}

def api_post(endpoint, path, payload, token, correlation):
	url=endpoint+path+"?apiVersion=v1&deploymentCorrelationId="+correlation
	request=Request(url, data=json.dumps(payload, separators=(",", ":")).encode("utf-8"), headers={"Authorization":"token "+token,"User-Agent":USER_AGENT,"Content-Type":"application/json; charset=utf-8"}, method="POST")
	try:
		with urlopen(request, timeout=API_TIMEOUT) as response:
			status=response.status
			body=response.read()
	except HTTPError as error:
		try:
			body=json.loads(error.read(65536))
			detail=value(body, "ErrorMessage") or value(value(body, "Response"), "ErrorMessage")
		except (ValueError, OSError):
			detail=None
		extra=": "+safe_message(detail, token) if detail else ""
		raise UploadError(path+" returned HTTP "+str(error.code)+extra, retryable=error.code in (408, 429) or error.code>=500) from None
	except (URLError, TimeoutError, OSError) as error:
		raise UploadError(path+" could not connect: "+safe_message(error, token), retryable=True) from None
	try:
		envelope=json.loads(body)
	except (ValueError, UnicodeDecodeError):
		raise UploadError(path+" returned invalid JSON.", retryable=True) from None
	envelope_status=value(envelope, "StatusCode")
	if status!=200 or envelope_status!=200:
		detail=value(envelope, "ErrorMessage")
		extra=": "+safe_message(detail, token) if detail else ""
		raise UploadError(path+" failed (HTTP "+str(status)+", Azure status "+str(envelope_status)+")"+extra, retryable=isinstance(envelope_status, int) and envelope_status>=500)
	return value(envelope, "Response")

def polling_info(response, slice_number):
	data=value(response, "PollingInfo")
	if not isinstance(data, dict) or not value(data, "Version") or not value(data, "DefaultHostname") or not value(data, "StageSiteIdentifier"):
		raise UploadError("Azure did not return a usable deployment polling identity.")
	return {"DefaultHostname":value(data, "DefaultHostname"),"StageSiteIdentifier":value(data, "StageSiteIdentifier"),"Version":value(data, "Version"),"TenantId":value(data, "TenantId"),"Slice":value(data, "Slice") if value(data, "Slice") is not None else slice_number,"GitHubRepoUrl":value(data, "GitHubRepoUrl")}

def marker_details(response, polling, files):
	if value(response, "CanSendMarkerFile") is not True:
		return None,set()
	version=polling["Version"]
	if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", version) or version in (".", ".."):
		raise UploadError("Azure returned an unsafe marker version.")
	name=version+"-aswa-markerfile.json"
	if any(item.archive_name==name for item in files):
		raise UploadError("The site contains a file reserved for Azure's marker format: "+name)
	remote=value(response, "FilesMap")
	if remote is not None and not isinstance(remote, dict):
		raise UploadError("Azure returned a malformed file map.")
	metadata={item.relative:{"sizeInBytes":item.size,"blobPath":None,"contentHash":item.md5,"lastModifiedTime":None} for item in files}
	content=base64.b64encode(gzip.compress(json.dumps(metadata, separators=(",", ":")).encode("utf-8"), mtime=0)).decode("ascii")
	skipped={item.relative for item in files if remote is not None and value(remote.get(item.relative), "ContentHash")==item.md5}
	return (name, content),skipped

def create_zip(temporary_file, files, marker, skipped):
	with zipfile.ZipFile(temporary_file, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True, strict_timestamps=False) as archive:
		for item in files:
			if item.relative in skipped:
				continue
			before=item.path.stat()
			if before.st_size!=item.size or before.st_mtime_ns!=item.mtime_ns:
				raise UploadError("A site file changed during ZIP creation: "+str(item.path))
			archive.write(item.path, item.archive_name)
			after=item.path.stat()
			if after.st_size!=item.size or after.st_mtime_ns!=item.mtime_ns:
				raise UploadError("A site file changed during ZIP creation: "+str(item.path))
		if marker is not None:
			archive.writestr(marker[0], marker[1])
	temporary_file.flush()
	size=temporary_file.tell()
	if size==0:
		raise UploadError("The upload ZIP is empty.")
	temporary_file.seek(0)
	with zipfile.ZipFile(temporary_file, "r") as archive:
		if archive.testzip() is not None:
			raise UploadError("The temporary ZIP failed its integrity check.")
	temporary_file.seek(0)
	return size

def upload_blob(uri, temporary_file, size, token):
	parts=urlsplit(uri)
	if parts.scheme!="https" or not parts.hostname or not parts.hostname.endswith(".blob.core.windows.net"):
		raise UploadError("Azure returned an unexpected Blob upload address.")
	query=parse_qs(parts.query)
	version=query.get("sv", [None])[0]
	if not version or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", version) or not query.get("sig"):
		raise UploadError("Azure returned a malformed Blob upload address.")
	headers={"Content-Type":"application/zip","Content-Length":str(size),"x-ms-blob-type":"BlockBlob","x-ms-date":format_datetime(datetime.now(timezone.utc), usegmt=True),"x-ms-version":version}
	connection=http.client.HTTPSConnection(parts.hostname, parts.port, timeout=BLOB_TIMEOUT)
	try:
		connection.request("PUT", parts.path+("?"+parts.query if parts.query else ""), body=temporary_file, headers=headers)
		response=connection.getresponse()
		status=response.status
		error_code=response.getheader("x-ms-error-code")
		response.read(65536)
	except (OSError, TimeoutError, http.client.HTTPException) as error:
		raise UploadError("Blob upload failed: "+safe_message(error, token)) from None
	finally:
		connection.close()
	if status!=201:
		detail=", Azure code "+error_code if error_code else ""
		raise UploadError("Blob upload failed (HTTP "+str(status)+detail+").")
	return status

def update_status(endpoint, event, info, polling, token, correlation, status):
	updated={**info,"Status":status}
	api_post(endpoint, "/api/upload/updatestatus", {"EventInfo":event,"UploadInfo":updated,"PollingInfo":polling}, token, correlation)

def pause(seconds):
	remaining=seconds
	while remaining>0:
		step=min(0.5, remaining)
		time.sleep(step)
		remaining-=step

def wait_for_deployment(endpoint, polling, token, correlation):
	deadline=time.monotonic()+POLL_LIMIT_SECONDS
	last_status=None
	failures=0
	while True:
		try:
			result=api_post(endpoint, "/api/upload/checkstatus", polling, token, correlation)
		except UploadError as error:
			if not error.retryable or failures>=2 or time.monotonic()>=deadline:
				raise UploadError("Could not confirm Azure deployment status; the final result is unknown. "+str(error)) from None
			failures+=1
			print("Status check failed; retrying (", failures, "/2): ", safe_message(error, token), sep="", file=sys.stderr, flush=True)
			pause(min(2+2**failures, max(0, deadline-time.monotonic())))
			continue
		failures=0
		status=value(result, "DeploymentStatus")
		if status!=last_status:
			print("Deployment status:", status or "unknown", flush=True)
			last_status=status
		if status=="Succeeded":
			regions=value(result, "UnhealthyRegions") or []
			if regions:
				print("Warning: Azure reported unhealthy regions:", ", ".join(regions), file=sys.stderr)
			return value(result, "SiteUrl") or polling["DefaultHostname"]
		if status=="Failed":
			detail=value(result, "ErrorDetails")
			raise UploadError("Azure deployment failed"+(": "+safe_message(detail, token) if detail else "."))
		if status!="InProgress":
			raise UploadError("Azure returned an unknown deployment status: "+safe_message(status, token))
		if time.monotonic()>=deadline:
			raise UploadError("Deployment status timed out after 10 minutes; the final result is unknown.")
		pause(min(POLL_SECONDS, max(0, deadline-time.monotonic())))

def deploy(folder, token):
	endpoint,slice_number=token_endpoint(token)
	files=inventory(folder)
	event=event_info(slice_number)
	info=upload_info(folder.expanduser().resolve(), files, slice_number)
	correlation=str(uuid.uuid4())
	print(f"Found {len(files)} files ({info['TotalAppSizeInBytes']} bytes).", flush=True)
	validation=api_post(endpoint, "/api/upload/validateapitoken", event, token, correlation)
	site=value(validation, "SiteUrl")
	if not site:
		raise UploadError("Azure did not identify a Static Web App for this token.")
	print("Azure site:", site, "| plan:", value(validation, "Sku") or "unknown", flush=True)
	print("Deploying this folder as the complete site.", flush=True)
	response=api_post(endpoint, "/api/upload/request", {"EventInfo":event,"UploadInfo":info,"PollingInfo":None}, token, correlation)
	polling=polling_info(response, slice_number)
	blob_uploaded=False
	try:
		if value(response, "AllowStagingEnvironments") is False:
			raise UploadError("Azure did not allow this deployment environment.")
		uri=value(value(response, "PackageUris"), "App")
		if not uri:
			raise UploadError("Azure did not return an app upload address.")
		marker,skipped=marker_details(response, polling, files)
		with tempfile.TemporaryFile(mode="w+b", dir=tempfile.gettempdir()) as temporary_file:
			size=create_zip(temporary_file, files, marker, skipped)
			print("Uploading ZIP:", size, "bytes; reused files:", len(skipped), flush=True)
			upload_blob(uri, temporary_file, size, token)
			blob_uploaded=True
		print("ZIP uploaded. Waiting for Azure to publish it.", flush=True)
	except Exception:
		if not blob_uploaded:
			try:
				update_status(endpoint, event, info, polling, token, correlation, "Failed")
			except UploadError as error:
				print("Warning: could not cancel Azure upload reservation:", safe_message(error, token), file=sys.stderr)
		raise
	try:
		update_status(endpoint, event, info, polling, token, correlation, "Succeeded")
	except UploadError as error:
		raise UploadError("ZIP uploaded, but Azure did not accept the status update; deployment result is unknown. "+safe_message(error, token)) from None
	result_url=wait_for_deployment(endpoint, polling, token, correlation)
	print("Deployment succeeded:", result_url, flush=True)
	return result_url

def main(argv=None):
	parser=argparse.ArgumentParser(description="Deploy a complete folder to Azure Static Web Apps using its deployment token.")
	parser.add_argument("folder", type=Path, help="Folder containing a root index.html and all files to publish")
	parser.add_argument("--token", help="Deployment token; omit to use "+TOKEN_ENV+" or a hidden prompt")
	args=parser.parse_args(argv)
	token=(args.token or os.environ.get(TOKEN_ENV) or "").strip()
	if not token:
		if not sys.stdin.isatty():
			print("Error: supply --token or set "+TOKEN_ENV+" when stdin is not interactive.", file=sys.stderr)
			return 2
		try:
			token=getpass.getpass("Deployment token: ").strip()
		except (EOFError, KeyboardInterrupt):
			print("\nCancelled.", file=sys.stderr)
			return 130
	try:
		deploy(args.folder, token)
		return 0
	except KeyboardInterrupt:
		print("\nCancelled. The temporary ZIP was closed and removed; check Azure if upload had already begun.", file=sys.stderr)
		return 130
	except (UploadError, OSError, ValueError, zipfile.BadZipFile) as error:
		print("Error:", safe_message(error, token), file=sys.stderr)
		return 1
	except Exception as error:
		print("Error: unexpected failure:", safe_message(error, token), file=sys.stderr)
		return 1

if __name__=="__main__":
	sys.exit(main())
