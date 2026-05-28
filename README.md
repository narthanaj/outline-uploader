# Outline Security Scan & Upload Action

A GitHub Action that:

1. Runs **Trivy** (and optionally Checkov) against the repository.
2. Renders the findings as Markdown.
3. Publishes them to a self-hosted [Outline](https://www.getoutline.com/) wiki in a per-app, scalable layout with retention.

> **v1.2.0 introduces a new per-app layout, UPDATE-or-CREATE for `latest`, an immutable history archive, and retention.** The legacy `publish-path` input still works but is deprecated. See [Migration](#migration-from-v111) below.

---

## Quickstart (new layout — recommended)

```yaml
permissions:
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Security Scan & Upload
        uses: narthanaj/outline-uploader@1.2.0
        with:
          api-key:        ${{ secrets.OUTLINE_API_KEY }}
          base-url:       ${{ secrets.OUTLINE_BASE_URL }}
          collection-id:  ${{ secrets.OUTLINE_COLLECTION_ID }}
          report-files:   'security-reports/*.json'
          short-code:     'NTH-AXT-FL-WA'   # app identifier
          component:      'iam'             # 'app' for single-image apps
          project-name:   'FleetLink'
          job-url:        '${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}'
```

> **Pin to a release tag** (e.g. `@1.2.0`), never `@main`.

The action then writes to:

```
reports/ci/nth-axt-fl-wa/iam/
├── latest                       ← UPDATEd in place on every run
└── history/
    └── 2026-05-28-7419ebf       ← immutable per-commit; pruned beyond retention-count
```

---

## Inputs

### Required

| Input | Description |
|---|---|
| `api-key` | Outline API key. **Must have Create + Update + Archive on the target collection.** |
| `base-url` | Outline instance base URL (`https://...`). |
| `collection-id` | Target collection UUID. |
| `report-files` | Comma-separated glob patterns for scan reports (e.g. `security-reports/*.json`). |

### New-layout mode (v1.2.0+)

| Input | Default | Description |
|---|---|---|
| `short-code` | `''` | App identifier (e.g. `NTH-AXT-FL-WA`). Use `_infra` for non-app scans (base-image-*, k8s-karpenter). **When set, activates the new layout.** |
| `component` | `app` | Sub-app component (matches `matrix.component`). Use `app` for single-image projects. |
| `retention-count` | `100` | History docs to keep per (app, component) before archiving oldest. Set to `0` to disable pruning. |
| `commit-sha` | `$GITHUB_SHA` | Commit SHA used for the history doc name. Auto-resolved from env if not set. |
| `dry-run` | `false` | Print resolved paths and exit without making API calls. |

### Cosmetic / metadata

| Input | Description |
|---|---|
| `project-name` | Human-readable project name embedded in the document body (e.g. `FleetLink`). |
| `job-url` | URL to the originating GH Actions run (linked in the report header). |

### Deprecated

| Input | Description |
|---|---|
| `publish-path` | Pre-v1.2 folder path (e.g. `Reports/CI`). Triggers legacy behaviour and emits a deprecation warning. Will be removed in v2.0. |

---

## Layout

```
[collection root]
└── reports
    └── ci
        ├── _infra                            ← non-app scans (base-image-daily, base-image-build, k8s-karpenter, ...)
        │   └── <scan-name>/
        │       ├── latest
        │       └── history/
        │           └── <YYYY-MM-DD>-<sha7>
        └── <short-code-lower>                ← e.g. nth-axt-fl-wa
            └── <component>                   ← 'app' for single-image; 'iam' / 'fleet' / ... for multi
                ├── latest                    ← UPDATE-or-CREATE on each scan
                └── history/                  ← immutable, bounded by retention-count
                    └── <YYYY-MM-DD>-<sha7>
```

Why this shape:

- **`<short-code-lower>` is the app key.** Same identifier the central pipeline uses for the IAM role (`<short-code-lower>-deploy-role`), AWS Secrets Manager prefix (`<short-code-lower>/*`), and the DockerHub repo name. One slug rules everything.
- **`latest` is mutable & deterministic-URL.** Operators bookmark `…/reports/ci/<app>/<component>/latest` and always see the most recent scan.
- **`history/<date>-<sha7>` is idempotent.** Same release re-cut = same title = UPDATE, not duplicate.
- **`_infra` prefix sorts infra scans separately** without requiring a second collection.

---

## Bootstrap (one-time per app)

Multi-shard matrix builds (e.g. one per microservice) hit Outline's `documents.search` concurrently and can race on folder creation. The included bootstrap script pre-creates the folder chain serially so the race window closes:

```bash
export OUTLINE_API_KEY=...
export OUTLINE_BASE_URL=https://outline.example.com
export OUTLINE_COLLECTION_ID=<uuid>

python3 scripts/bootstrap-app-folders.py \
  --short-code NTH-AXT-FL-WA \
  --components iam,fleet,telematics,audit \
  --project-name "FleetLink"
```

The script is idempotent — re-runs are a no-op (every lookup returns "found existing").

Recommended: wire this into your app-onboarding flow (e.g. `onboard_ec2_role.sh`) so every new app gets the skeleton before its first release.

---

## Migration from v1.1.1

| Caller passes today | Replace with |
|---|---|
| `publish-path: 'reports/ci/<image>(<project>)/commit_scan'` | `short-code: '<short-code>'`<br>`component: '<matrix.component>'` (or omit for `app`) |
| `publish-path: 'reports/ci/devops/base_image_daily_scan'` | `short-code: '_infra'`<br>`component: 'base-image-daily'` |
| `publish-path: 'reports/ci/k8s/commit_scan'` | `short-code: '_infra'`<br>`component: 'k8s-karpenter'` |

You can migrate workflows one at a time — `v1.2.0` runs the new layout when `short-code` is set, and falls back to the legacy code path (with a deprecation warning) for callers that still pass `publish-path`.

Existing scan history under the old path is left in place — old URLs keep working. Archive the legacy folders in the Outline UI on your own schedule when the new layout is fully populated.

---

## Scans performed

- **Trivy** (v0.69.3, checksum-pinned): repo-wide vuln + config + secret scan.
- **Checkov** (only if the `checkov` CLI is on PATH AND an `infrastructure/` directory exists). The action no longer installs Checkov by default — adopters who need it should install it explicitly in a prior step.

---

## Supply-chain security

- **Trivy** is downloaded as a versioned release tarball and verified against a SHA-256 checksum before extraction.
- **Python packages** are version-pinned in `requirements.txt`. v1.2.0 dropped `checkov==3.2.361` and its ~70 transitive deps because the action only needs `requests` for the Outline API client.
- The **API key** is read from `OUTLINE_API_KEY` env (never passed as a CLI argument).
- **`publish: true`** documents are visible only to users with read access to the collection — control collection-level permissions in Outline, not in the action.

---

## Recommendations for callers

1. **Set minimal permissions** — `permissions: { contents: read }` at the job level.
2. **Do not run on fork PRs** — the action needs secrets that fork PRs cannot access.
3. **Make Outline upload `continue-on-error: true`** — a transient Outline outage should never block your deploy gate. The action's own deploy job already does this in `Zuse-Technologies/DevOps/main-pipeline.yml`.
4. **One bootstrap per app** at onboarding time, before the first release dispatches.
