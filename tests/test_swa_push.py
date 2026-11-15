import base64
import contextlib
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import swa_push

GUID="00000000-0000-0000-0000-000000000000"
TOKEN="a"*64+"5-"+GUID+"003"
BLOB_URL="https://example.blob.core.windows.net/container/app.zip?sv=2023-11-03&sp=w&sig=fake"

class FakeResponse:
	def __init__(self, body, status=200):
		self.body=body
		self.status=status
	def __enter__(self):
		return self
	def __exit__(self, exception_type, exception, traceback):
		return False
	def read(self, size=-1):
		return self.body
	def getheader(self, name):
		return None

class UploadTests(unittest.TestCase):
	def site_folder(self, root):
		folder=Path(root)
		(folder/"index.html").write_text("<h1>Hello</h1>", encoding="utf-8")
		(folder/"css").mkdir()
		(folder/"css"/"site.css").write_text("body{}", encoding="utf-8")
		return folder

	def responses(self, calls, states):
		def respond(endpoint, path, payload, token, correlation):
			calls.append((path, payload))
			if path=="/api/upload/validateapitoken":
				return {"siteUrl":"example.azurestaticapps.net","sku":"Free"}
			if path=="/api/upload/request":
				return {"packageUris":{"app":BLOB_URL},"pollingInfo":{"defaultHostname":"example.azurestaticapps.net","stageSiteIdentifier":"master","version":"v123"},"canSendMarkerFile":False}
			if path=="/api/upload/updatestatus":
				return None
			if path=="/api/upload/checkstatus":
				return next(states)
			raise AssertionError(path)
		return respond

	def test_token_routes_and_rejects_legacy(self):
		self.assertEqual(swa_push.token_endpoint(TOKEN), ("https://content-am2.infrastructure.5.azurestaticapps.net", 5))
		self.assertEqual(swa_push.token_endpoint("a"*64+"-"+GUID+"00f"+"x"), ("https://content-eus2.infrastructure.azurestaticapps.net", 0))
		with self.assertRaisesRegex(swa_push.UploadError, "legacy v0"):
			swa_push.token_endpoint("a"*64+"-"+GUID+"003")
		with self.assertRaises(swa_push.UploadError):
			swa_push.token_endpoint("a"*64+"9-"+GUID+"003")

	def test_inventory_requires_exact_root_index_and_zip_paths(self):
		with tempfile.TemporaryDirectory() as directory:
			folder=Path(directory)
			(folder/"Index.html").write_text("wrong case", encoding="utf-8")
			with self.assertRaisesRegex(swa_push.UploadError, "index.html"):
				swa_push.inventory(folder)
			(folder/"Index.html").unlink()
			self.site_folder(folder)
			files=swa_push.inventory(folder)
			self.assertEqual({item.archive_name for item in files}, {"index.html", "css/site.css"})
			with tempfile.TemporaryFile(mode="w+b", dir=tempfile.gettempdir()) as temporary_file:
				name=temporary_file.name
				swa_push.create_zip(temporary_file, files, None, set())
				with zipfile.ZipFile(temporary_file) as archive:
					self.assertEqual(set(archive.namelist()), {"index.html", "css/site.css"})
				if os.name=="nt":
					self.assertTrue(Path(name).is_file())
			if os.name=="nt":
				self.assertFalse(Path(name).exists())

	def test_repository_metadata_is_omitted_without_deleting_it(self):
		with tempfile.TemporaryDirectory() as directory:
			folder=self.site_folder(directory)
			(folder/".git").mkdir()
			(folder/".git"/"config").write_text("private", encoding="utf-8")
			(folder/".github").mkdir()
			(folder/".github"/"workflow.yml").write_text("private", encoding="utf-8")
			(folder/"css"/".git").mkdir()
			(folder/"css"/".git"/"config").write_text("private", encoding="utf-8")
			files=swa_push.inventory(folder)
			self.assertEqual({item.archive_name for item in files}, {"index.html", "css/site.css"})
			self.assertTrue((folder/".git"/"config").is_file())
			self.assertTrue((folder/".github"/"workflow.yml").is_file())
			self.assertTrue((folder/"css"/".git"/"config").is_file())

	def test_marker_contains_complete_site_map(self):
		with tempfile.TemporaryDirectory() as directory:
			files=swa_push.inventory(self.site_folder(directory))
			index=next(item for item in files if item.archive_name=="index.html")
			marker,skipped=swa_push.marker_details({"canSendMarkerFile":True,"filesMap":{index.relative:{"contentHash":index.md5}}}, {"Version":"v123"}, files)
			self.assertEqual(skipped, {index.relative})
			decoded=json.loads(gzip.decompress(base64.b64decode(marker[1])))
			self.assertEqual(set(decoded), {item.relative for item in files})
			self.assertEqual(decoded[index.relative]["contentHash"], index.md5)
			with tempfile.TemporaryFile(mode="w+b", dir=tempfile.gettempdir()) as temporary_file:
				swa_push.create_zip(temporary_file, files, marker, skipped)
				with zipfile.ZipFile(temporary_file) as archive:
					self.assertEqual(set(archive.namelist()), {"css/site.css", "v123-aswa-markerfile.json"})

	def test_api_request_uses_token_and_lower_camel_response(self):
		requests=[]
		def open_fake(request, timeout):
			requests.append(request)
			self.assertEqual(timeout, swa_push.API_TIMEOUT)
			return FakeResponse(b'{"response":{"sku":"Free"},"statusCode":200,"errorMessage":""}')
		with patch.object(swa_push, "urlopen", side_effect=open_fake):
			result=swa_push.api_post("https://content-am2.infrastructure.5.azurestaticapps.net", "/api/upload/validateapitoken", {}, TOKEN, "id")
		self.assertEqual(result["sku"], "Free")
		self.assertEqual(requests[0].get_header("Authorization"), "token "+TOKEN)

	def test_errors_redact_token_and_signed_url(self):
		message="server echoed "+TOKEN+" and "+BLOB_URL
		clean=swa_push.safe_message(message, TOKEN)
		self.assertNotIn(TOKEN, clean)
		self.assertNotIn("sig=fake", clean)

	def test_blob_put_streams_zip_without_token_header(self):
		class Connection:
			def __init__(self, host, port, timeout):
				self.host=host
				self.timeout=timeout
			def request(self, method, path, body, headers):
				self.method=method
				self.path=path
				self.headers=headers
				self.body=body.read()
			def getresponse(self):
				return FakeResponse(b"", 201)
			def close(self):
				pass
		instances=[]
		def connection(host, port, timeout):
			item=Connection(host, port, timeout)
			instances.append(item)
			return item
		with tempfile.TemporaryFile(mode="w+b", dir=tempfile.gettempdir()) as temporary_file:
			temporary_file.write(b"ZIP")
			temporary_file.seek(0)
			with patch.object(swa_push.http.client, "HTTPSConnection", side_effect=connection):
				self.assertEqual(swa_push.upload_blob(BLOB_URL, temporary_file, 3, TOKEN), 201)
		self.assertEqual(instances[0].method, "PUT")
		self.assertEqual(instances[0].body, b"ZIP")
		self.assertEqual(instances[0].headers["Content-Length"], "3")
		self.assertNotIn("Authorization", instances[0].headers)

	def test_full_upload_and_failure_status(self):
		with tempfile.TemporaryDirectory() as directory:
			folder=self.site_folder(directory)
			calls=[]
			output=io.StringIO()
			states=iter([{"deploymentStatus":"InProgress"},{"deploymentStatus":"Succeeded","siteUrl":"https://example.azurestaticapps.net"}])
			with patch.object(swa_push, "api_post", side_effect=self.responses(calls, states)), patch.object(swa_push, "upload_blob", return_value=201), patch.object(swa_push, "pause"), contextlib.redirect_stdout(output):
				self.assertEqual(swa_push.deploy(folder, TOKEN), "https://example.azurestaticapps.net")
			self.assertIn("Deployment succeeded", output.getvalue())
			self.assertNotIn(TOKEN, output.getvalue())
			self.assertEqual([path for path,_ in calls], ["/api/upload/validateapitoken", "/api/upload/request", "/api/upload/updatestatus", "/api/upload/checkstatus", "/api/upload/checkstatus"])
			self.assertEqual(calls[2][1]["UploadInfo"]["Status"], "Succeeded")
			calls=[]
			with patch.object(swa_push, "api_post", side_effect=self.responses(calls, iter([]))), patch.object(swa_push, "upload_blob", side_effect=swa_push.UploadError("Blob HTTP 403")), contextlib.redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(swa_push.UploadError, "403"):
					swa_push.deploy(folder, TOKEN)
			self.assertEqual(calls[-1][1]["UploadInfo"]["Status"], "Failed")

	def test_status_poll_retries_transient_errors(self):
		polling={"DefaultHostname":"example.azurestaticapps.net"}
		responses=[swa_push.UploadError("temporary HTTP 503", retryable=True),{"deploymentStatus":"Succeeded","siteUrl":"https://example.azurestaticapps.net"}]
		def check(*args):
			result=responses.pop(0)
			if isinstance(result, Exception):
				raise result
			return result
		with patch.object(swa_push, "api_post", side_effect=check) as post, patch.object(swa_push, "pause") as pause, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
			self.assertEqual(swa_push.wait_for_deployment("https://host", polling, TOKEN, "id"), "https://example.azurestaticapps.net")
		self.assertEqual(post.call_count, 2)
		self.assertEqual(pause.call_count, 1)

	@unittest.skipUnless(os.name=="nt", "Windows temporary file path check")
	def test_ctrl_c_during_upload_closes_temporary_zip(self):
		with tempfile.TemporaryDirectory() as directory:
			folder=self.site_folder(directory)
			created=[]
			real_temporary_file=tempfile.TemporaryFile
			def make_temporary_file(*args, **kwargs):
				file=real_temporary_file(*args, **kwargs)
				created.append(Path(file.name))
				return file
			calls=[]
			with patch.object(swa_push, "api_post", side_effect=self.responses(calls, iter([]))), patch.object(swa_push.tempfile, "TemporaryFile", side_effect=make_temporary_file), patch.object(swa_push, "upload_blob", side_effect=KeyboardInterrupt), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				self.assertEqual(swa_push.main([str(folder), "--token", TOKEN]), 130)
			self.assertEqual(len(created), 1)
			self.assertFalse(created[0].exists())

	@unittest.skipUnless(os.name=="nt", "Windows delete-on-close behavior")
	def test_system_temp_file_disappears_after_abrupt_stop(self):
		code="import os,tempfile; f=tempfile.TemporaryFile(mode='w+b',dir=tempfile.gettempdir()); print(f.name,flush=True); f.write(b'ZIP'); os._exit(9)"
		result=subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=10)
		self.assertEqual(result.returncode, 9)
		name=Path(result.stdout.strip())
		self.assertEqual(name.parent, Path(tempfile.gettempdir()))
		self.assertFalse(name.exists())

if __name__=="__main__":
	unittest.main()
