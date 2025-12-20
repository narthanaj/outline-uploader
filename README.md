# Outline Uploader GitHub Action

A GitHub Action to upload security scan reports (Checkov, Trivy) to a self-hosted [Outline](https://www.getoutline.com/) instance.

## Usage

```yaml
steps:
  - name: Upload to Outline
    uses: narthanaj/outline-uploader@main
    with:
      api-key: ${{ secrets.OUTLINE_API_KEY }}
      base-url: ${{ secrets.OUTLINE_BASE_URL }}
      collection-id: ${{ secrets.OUTLINE_COLLECTION_ID }}
      report-files: 'security-reports/*.json'
      job-url: "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
```

## Inputs

| Input | Description | Required |
|---|---|---|
| `api-key` | Your Outline API Key. | Yes |
| `base-url` | The base URL of your Outline instance (e.g. `https://docs.mycompany.com`). | Yes |
| `collection-id` | The ID of the collection to publish to. | Yes |
| `report-files` | Glob pattern for the report files (comma separated). | Yes |
| `job-url` | Optional URL to link back to the CI job. | No |
