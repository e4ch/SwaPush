# SwaPush notes

Best effort: the upload API described here is non-public, reconstructed through reverse engineering, and can change at any moment.

## Scope

Publish one complete static site from a local directory with a root `index.html` and a current Azure Static Web Apps deployment token. Python 3.12+ standard library only; no Node.js/npm, GitHub integration, Microsoft executable, or admin privileges. A UI may be added later. The CLI targets production and accepts only the selected site's root config (`staticwebapp.config.json` or `routes.json`).

All regular files are inventoried recursively with no extension allowlist, except entries named `.git` or `.github` (at any depth). Source files are never deleted. Symlinks, junctions, unreadable files, and files changed while packaging cause a clear failure to avoid incomplete deployments. The chosen directory represents the entire desired site; this is not a subfolder update.

## Private protocol observed

The token determines the regional content-distribution endpoint. The client validates the token via `POST /api/upload/validateapitoken`, requests upload with `POST /api/upload/request`, sends the site's ZIP to the returned write-only Blob SAS URL, reports `Succeeded` via `POST /api/upload/updatestatus`, then polls `POST /api/upload/checkstatus`. A failed transfer reports `Failed` where possible. API calls use `Authorization: token <deployment-token>` and a correlation ID, not Bearer authentication. The service may return an optional `FilesMap` and enable a marker file that represents the full logical file set while unchanged bytes are reused. This is not a read or listing API. There is no documented remote-file enumeration or download endpoint.

The ZIP is opened with `tempfile.TemporaryFile` in the calling user's system temp directory, streamed directly, and closed on completion or error. On Windows it is also deleted after abrupt process termination. Network operations use short timeouts; polling waits are interruptible. If stopped after ZIP transfer, Azure may still complete deployment, so the result is unknown until checked in Azure.

## Decisions and verification

The official [npm deploy wrapper](https://github.com/Azure/static-web-apps-cli/blob/main/src/cli/commands/deploy/deploy.ts) selects paths and token, optionally uses Azure login, supports preview environments and external config, downloads/runs Microsoft's uploader, and does no file-extension filtering. Those optional modes, Azure Functions, Data API, and build steps are outside this tool's two-input scope. Microsoft's client omits `.git` and `.github` in one layout; SwaPush omits them without altering source files.

Run `python -m unittest discover -s tests -v` for offline tests covering token routing, upload protocol, archive and marker content, result handling, redaction, metadata exclusion, and temporary-file cleanup. The public CLI has also completed a live deployment, followed by successful hash verification of the published files. The protocol is private and may change.
