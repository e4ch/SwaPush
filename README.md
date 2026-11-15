# SwaPush

SwaPush publishes a complete local folder to an Azure Static Web App using its deployment token. It is a single Python script with no third-party packages, Node.js/npm, GitHub deployment workflow, Microsoft executable, or administrator rights required.

**Best effort:** This tool uses a non-public Azure deployment API reconstructed through reverse engineering. Microsoft can change that API at any moment, so uploads may stop working without notice.

## Requirements and behavior

- The folder must contain `index.html` at its root. That folder becomes the **entire production site**, so include existing pages and assets you want to keep. Uploading one subfolder alone makes it the new site root.
- Every file type is eligible for upload, including images, fonts, and PDFs. Entries named `.git` or `.github` are omitted from the upload without changing the local folder. Review the rest of the folder before publishing it.
- A current Azure Static Web Apps deployment token is required. The script prompts for it without echoing, or reads `AZURE_STATIC_WEB_APPS_API_TOKEN`. `--token` is supported but exposes the value in shell history and process arguments.
- A ZIP is created in the user's system temporary folder, streamed to Azure, and removed on success, failure, or Ctrl-C; on Windows, the temp file also disappears after abrupt process termination. Network calls have 10-second timeouts and polling waits use short sleeps to limit Ctrl-C delays. The script prints progress, the deployment result, and sanitized errors. Ctrl-C returns exit code 130.
- This is a full static-site deployment. It does not provide per-file remote editing, remote file enumeration or download, build steps, Azure Functions, Data API deployment, or named preview environments.

## Run

Use Python 3.12 or newer:

```powershell
python .\swa_push.py 'C:\path\to\site'
```

The script prompts for the token. For unattended use, set `AZURE_STATIC_WEB_APPS_API_TOKEN` in the process environment. Exit code 0 means Azure confirmed success; 1 means failure or an unknown result; 2 means a missing token in a noninteractive session.

Run the standard-library tests with `python -m unittest discover -s tests -v`. See [documentation.md](documentation.md) for protocol notes and limitations.

## Origin and status

This independent implementation was developed by examining Microsoft's open-source [Static Web Apps CLI npm package](https://github.com/Azure/static-web-apps-cli) and reverse engineering its `StaticSitesClient` uploader. The npm wrapper delegates packaging and upload to that executable. SwaPush implements the observed HTTP sequence in Python; it neither downloads nor runs the executable, and does not include Microsoft binaries or decompiled source. SwaPush has passed offline tests and a live deployment, with the published files verified against their local hashes.

## License

[MIT License](LICENSE). Attribution is retained through its copyright and permission notice.
