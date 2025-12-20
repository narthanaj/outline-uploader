# Outline Security Scan & Upload Action

A GitHub Action that:
1.  Installs **Checkov** and **Trivy**.
2.  Runs security scans on your repository.
3.  Uploads the findings to a self-hosted [Outline](https://www.getoutline.com/) instance.

## Usage

```yaml
steps:
  - name: Security Scan & Upload
    uses: narthanaj/outline-uploader@main
    with:
      api-key: ${{ secrets.OUTLINE_API_KEY }}
      base-url: ${{ secrets.OUTLINE_BASE_URL }}
      collection-id: ${{ secrets.OUTLINE_COLLECTION_ID }}
      # Optional: report-files defaults to the generated reports, but you can override if needed
      # report-files: 'security-reports/*.json'
      job-url: "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
```

## Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `api-key` | Your Outline API Key. | Yes | N/A |
| `base-url` | The base URL of your Outline instance. | Yes | N/A |
| `collection-id` | The ID of the collection to publish to. | Yes | N/A |
| `report-files` | Glob pattern for the report files. | No | `security-reports/*.json` |
| `job-url` | Optional URL to link back to the CI job. | No | N/A |

## Scans Performed

-   **Checkov**: Scans `infrastructure/` directory for IaC misconfigurations.
-   **Trivy**: Scans the entire repository (`.`) for vulnerabilities, secrets, and config issues.
