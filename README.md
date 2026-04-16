# Outline Security Scan & Upload Action

A GitHub Action that:
1.  Installs **Checkov** and **Trivy** (pinned versions with integrity verification).
2.  Runs security scans on your repository.
3.  Uploads the findings as formatted Markdown to a self-hosted [Outline](https://www.getoutline.com/) instance.

## Usage

```yaml
permissions:
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Security Scan & Upload
        uses: narthanaj/outline-uploader@1.1.1
        with:
          api-key: ${{ secrets.OUTLINE_API_KEY }}
          base-url: ${{ secrets.OUTLINE_BASE_URL }}
          collection-id: ${{ secrets.OUTLINE_COLLECTION_ID }}
          report-files: 'security-reports/*.json'
          publish-path: 'Reports/CI'
          job-url: "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
```

> **Important**: Always pin to a release tag (e.g. `@1.1.1`), not `@main`.

## Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `api-key` | Your Outline API Key. Passed securely via environment variable. | Yes | N/A |
| `base-url` | The base URL of your Outline instance (must be HTTPS). | Yes | N/A |
| `collection-id` | The UUID of the Outline collection to publish to. | Yes | N/A |
| `report-files` | Comma-separated glob patterns for report files. | Yes | N/A |
| `publish-path` | Folder hierarchy in Outline (e.g. `Reports/CI/K8s`). | No | `''` (root) |
| `job-url` | URL linking back to the GitHub Actions run. | No | N/A |

## Scans Performed

-   **Checkov**: Scans the `infrastructure/` directory for IaC misconfigurations.
-   **Trivy** (v0.69.3): Scans the entire repository for vulnerabilities, secrets, and misconfigurations.

## Supply Chain Security

All external dependencies are integrity-verified:

- **Trivy** is downloaded as a versioned release tarball and verified against a SHA-256 checksum before extraction.
- **Python packages** (`requests`, `checkov`) are version-pinned in `requirements.txt` to prevent uncontrolled dependency updates.
- The **API key** is read from an environment variable internally and is never passed as a CLI argument.

## Security Recommendations for Callers

1. **Set minimal permissions** -- Always include `permissions: { contents: read }` in your workflow to limit the GitHub token scope.
2. **Do not run on fork PRs** -- This action requires secrets. Use `push`, `workflow_dispatch`, or `pull_request_target` (with careful checkout control) as triggers. Running on `pull_request` from untrusted forks will expose your secrets.
3. **Store all secrets in GitHub Secrets** -- Never hardcode `api-key`, `base-url`, or `collection-id` in workflow files.
