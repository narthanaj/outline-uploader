import os
import re
import json
import time
import argparse
import requests
import glob
import datetime

# =============================================================================
# Outline Uploader v1.2.0
# =============================================================================
# Two operating modes, picked by --short-code:
#
#   * NEW LAYOUT (--short-code NTH-AXT-FL-WA --component iam ...)
#       reports/ci/<short-code-lower>/<component>/latest           ← UPDATE-or-CREATE
#       reports/ci/<short-code-lower>/<component>/history/<date>-<sha7>  ← immutable
#       Plus retention: archive history docs beyond --retention-count.
#       Use _infra as short-code for non-app scans (base-image-*, k8s-karpenter).
#
#   * LEGACY (--publish-path "Reports/CI/X")
#       Original behaviour: one doc per run titled "Scan: <timestamp>"
#       Kept for backward compat. Will be removed in v2.0.
#
# Hardening:
#   * ensure_path() retries on empty search results (3x w/ exponential backoff)
#     to absorb Outline read-replica timing under parallel matrix shards —
#     this is the root cause of "duplicate ci/ folders every trigger" that
#     prompted this rewrite.
# =============================================================================

# Default report timestamps include timezone offset for clarity.
REPORT_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M %z'
# Titles omit timezone offsets (e.g., +HHMM) to avoid special characters in document names.
TITLE_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M'
# History doc title prefix: date-only so same-day re-runs of the SAME commit
# land in the SAME doc (idempotent UPDATE), and chronological alpha-sort holds.
HISTORY_DATE_FORMAT = '%Y-%m-%d'

# Folder ensure_path retry policy. Tunes how aggressively we re-try a search
# that returned "not found" before deciding to create a duplicate. 3 retries
# at 250ms / 500ms / 1000ms covers the typical Outline replication window.
ENSURE_PATH_RETRIES = 3
ENSURE_PATH_BACKOFF_MS = 250


# -----------------------------------------------------------------------------
# Report parsing (unchanged from v1.1.1)
# -----------------------------------------------------------------------------

def parse_checkov(file_path):
    if not os.path.exists(file_path):
        return []

    findings = []
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            if not content.strip():
                return []
            data = json.loads(content)

        if isinstance(data, dict):
            data = [data]

        for result in data:
            if 'results' in result and 'failed_checks' in result['results']:
                for check in result['results']['failed_checks']:
                    findings.append({
                        'tool': 'Checkov',
                        'severity': 'HIGH',
                        'id': check.get('check_id'),
                        'description': check.get('check_name'),
                        'resource': check.get('resource'),
                        'file': check.get('file_path'),
                    })
    except Exception as e:
        print(f"Error parsing Checkov file {file_path}: {e}")

    return findings


def parse_trivy(file_path):
    if not os.path.exists(file_path):
        return []

    findings = []
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            if not content.strip():
                return []
            data = json.loads(content)

        if 'Results' in data:
            for result in data['Results']:
                target = result.get('Target', 'Unknown')
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        findings.append({
                            'tool': 'Trivy',
                            'severity': vuln.get('Severity', 'UNKNOWN'),
                            'id': vuln.get('VulnerabilityID'),
                            'description': vuln.get('Title', 'No description'),
                            'resource': vuln.get('PkgName'),
                            'file': target,
                            'fixed_version': vuln.get('FixedVersion', 'N/A')
                        })
                if 'Misconfigurations' in result:
                    for misconf in result['Misconfigurations']:
                        findings.append({
                            'tool': 'Trivy (Misconfig)',
                            'severity': misconf.get('Severity', 'UNKNOWN'),
                            'id': misconf.get('ID'),
                            'description': misconf.get('Title', 'No description'),
                            'resource': misconf.get('Title'),
                            'file': target,
                        })
    except Exception as e:
        print(f"Error parsing Trivy file {file_path}: {e}")

    return findings


def get_severity_weight(severity):
    weights = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    return weights.get(severity.upper(), 10)


def localized_timestamp(format_string=REPORT_TIMESTAMP_FORMAT):
    localized_now = datetime.datetime.now(datetime.timezone.utc).astimezone()
    return localized_now.strftime(format_string)


def generate_markdown(findings, job_url, project_name=None, short_code=None, component=None, commit_sha=None):
    timestamp_str = localized_timestamp()
    total_issues = len(findings)

    findings.sort(key=lambda x: get_severity_weight(x['severity']))

    severity_counts = {}
    for f in findings:
        sev = f['severity'].upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    md = "# 🛡️ Security Scan Report\n\n"
    if project_name:
        md += f"**Project**: {project_name}  \n"
    if short_code:
        md += f"**Short code**: `{short_code}`  \n"
    if component and component != 'app':
        md += f"**Component**: `{component}`  \n"
    if commit_sha:
        md += f"**Commit**: `{commit_sha}`  \n"
    md += f"**Timestamp**: {timestamp_str}  \n"
    if job_url:
        md += f"**Source Job**: [View in GitHub]({job_url})\n\n"

    md += "## 📊 Executive Summary\n\n"

    if total_issues == 0:
        md += "✅ **No security issues found!** Your code looks clean.\n\n"
        return md

    md += f"Found **{total_issues}** potential issues.\n\n"

    md += "| Critical 🔴 | High 🟠 | Medium 🟡 | Low 🔵 |\n"
    md += "|:---:|:---:|:---:|:---:|\n"
    md += f"| {severity_counts.get('CRITICAL', 0)} | {severity_counts.get('HIGH', 0)} | {severity_counts.get('MEDIUM', 0)} | {severity_counts.get('LOW', 0)} |\n\n"

    md += "## 🔍 Detailed Findings\n\n"

    current_sev = None
    for f in findings:
        sev = f['severity'].upper()
        if sev != current_sev:
            current_sev = sev
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(sev, '⚪')
            md += f"### {icon} {sev} Priority\n\n"

        desc = f['description'].replace('|', ' ') if f['description'] else 'No Description'
        resource = f['resource'] if f.get('resource') else 'N/A'

        md += f"#### [{f['tool']}] {f['id']}: {desc[:80]}...\n\n"
        md += f"- **Resource**: `{resource}`\n"
        md += f"- **File**: `{f['file']}`\n"
        if f.get('fixed_version') and f['fixed_version'] != 'N/A':
            md += f"- **Fixed Version**: `{f['fixed_version']}`\n"
        md += f"\n> {desc}\n\n"

    md += "---\n*Report generated by Outline Uploader Action (v1.2)*"
    return md


# -----------------------------------------------------------------------------
# Outline API helpers
# -----------------------------------------------------------------------------

def headers(api_key):
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def find_document(api_key, base_url, collection_id, title, parent_id=None):
    """Search for a document by title within a parent (case-insensitive).

    Returns the document ID or None. Folder lookup happens here — see
    find_document_with_retry() for the race-hardened wrapper used by
    ensure_path().
    """
    url = f"{base_url.rstrip('/')}/api/documents.search"
    payload = {
        "collectionId": collection_id,
        "query": title,
        "includeArchived": False,
        "limit": 10,
    }
    try:
        response = requests.post(url, headers=headers(api_key), json=payload)
        response.raise_for_status()
        results = response.json().get('data', [])
        for doc in results:
            if doc['document']['title'].lower() == title.lower():
                if parent_id:
                    if doc['document'].get('parentDocumentId') == parent_id:
                        return doc['document']['id']
                elif doc['document'].get('parentDocumentId') is None:
                    return doc['document']['id']
    except Exception as e:
        print(f"Warning: Could not search for document '{title}': {e}")
    return None


def find_document_with_retry(api_key, base_url, collection_id, title, parent_id=None,
                             retries=ENSURE_PATH_RETRIES, backoff_ms=ENSURE_PATH_BACKOFF_MS):
    """find_document() wrapped with exponential backoff on empty results.

    Why: Outline's documents.search hits a read replica that can lag behind
    the primary by hundreds of milliseconds after a documents.create. Under
    matrix parallelism (e.g. FleetLink's 4 simultaneous scan shards) the
    second shard's search for an existing `ci/` folder returns empty even
    though the first shard JUST created it. Without retry, every shard
    independently calls documents.create and we get duplicate siblings.

    Retries: 250ms, 500ms, 1000ms (doubling). Returns None only after
    `retries` empty results in a row — at which point the folder truly
    doesn't exist and ensure_path() is justified in creating it.
    """
    doc_id = find_document(api_key, base_url, collection_id, title, parent_id)
    if doc_id:
        return doc_id

    delay = backoff_ms / 1000.0
    for attempt in range(1, retries + 1):
        time.sleep(delay)
        doc_id = find_document(api_key, base_url, collection_id, title, parent_id)
        if doc_id:
            print(f"  (found '{title}' on retry {attempt} after {int(delay * 1000)}ms)")
            return doc_id
        delay *= 2
    return None


def create_document(api_key, base_url, collection_id, title, parent_id=None, text=""):
    url = f"{base_url.rstrip('/')}/api/documents.create"
    payload = {
        "collectionId": collection_id,
        "title": title,
        "text": text,
        "publish": True,
    }
    if parent_id:
        payload["parentDocumentId"] = parent_id

    response = requests.post(url, headers=headers(api_key), json=payload)
    if response.status_code == 200:
        return response.json()['data']['id']
    raise Exception(f"Failed to create document '{title}': {response.text}")


def update_document(api_key, base_url, doc_id, text, title=None):
    """POST /api/documents.update — overwrite the body (and optionally title).

    Used for the mutable `latest` doc + for re-cuts of the same commit SHA
    that should land in the same history doc.
    """
    url = f"{base_url.rstrip('/')}/api/documents.update"
    payload = {"id": doc_id, "text": text, "publish": True, "append": False}
    if title:
        payload["title"] = title
    response = requests.post(url, headers=headers(api_key), json=payload)
    if response.status_code == 200:
        return response.json()['data']['id']
    raise Exception(f"Failed to update document '{doc_id}': {response.text}")


def upsert_document(api_key, base_url, collection_id, title, parent_id, text, skip_create=False):
    """UPDATE if a doc with (title, parent_id) exists; CREATE otherwise.

    skip_create: when True, raise instead of creating — used by bootstrap
    callers that want strict mode (folders must already exist).
    """
    doc_id = find_document_with_retry(api_key, base_url, collection_id, title, parent_id)
    if doc_id:
        print(f"Updating document '{title}' (id={doc_id})")
        return update_document(api_key, base_url, doc_id, text)
    if skip_create:
        raise Exception(f"Document '{title}' not found under parent and skip_create=True")
    print(f"Creating document '{title}'")
    return create_document(api_key, base_url, collection_id, title, parent_id, text)


def list_documents_by_parent(api_key, base_url, collection_id, parent_id, limit=200):
    """POST /api/documents.list — enumerate docs under a parent.

    Used by apply_retention(). Outline's API returns up to `limit` per call;
    we pull a single page since retention typically only needs to compare
    ~100 docs. If you ever raise --retention-count beyond ~200, this needs
    pagination via the `offset` parameter.
    """
    url = f"{base_url.rstrip('/')}/api/documents.list"
    payload = {
        "collectionId": collection_id,
        "parentDocumentId": parent_id,
        "sort": "createdAt",
        "direction": "DESC",
        "limit": limit,
    }
    response = requests.post(url, headers=headers(api_key), json=payload)
    response.raise_for_status()
    return response.json().get('data', [])


def archive_document(api_key, base_url, doc_id):
    """POST /api/documents.archive — soft-delete (recoverable in Outline trash).

    Used by apply_retention() for prune-beyond-count. Archive instead of
    delete so SOC2 / audit retention never loses a report — operators can
    restore from the Outline Archive view if needed.
    """
    url = f"{base_url.rstrip('/')}/api/documents.archive"
    response = requests.post(url, headers=headers(api_key), json={"id": doc_id})
    response.raise_for_status()


def apply_retention(api_key, base_url, collection_id, history_parent_id, retention_count):
    """Archive history docs beyond `retention_count` (oldest first).

    No-op when retention_count <= 0 (keep everything). Wrapped by the caller
    in try/except so a failed prune cannot fail the upload — better to leak
    a doc than to break the deploy gate report.
    """
    if retention_count <= 0:
        return
    docs = list_documents_by_parent(api_key, base_url, collection_id, history_parent_id)
    if len(docs) <= retention_count:
        return
    # docs are sorted DESC by createdAt — the oldest are at the end.
    to_archive = docs[retention_count:]
    print(f"Retention: archiving {len(to_archive)} doc(s) beyond keep-{retention_count}")
    for doc in to_archive:
        doc_id = doc['id']
        title = doc.get('title', '<untitled>')
        try:
            archive_document(api_key, base_url, doc_id)
            print(f"  archived: {title}")
        except Exception as e:
            print(f"  WARN: failed to archive '{title}' ({doc_id}): {e}")


def ensure_path(api_key, base_url, collection_id, path):
    """Walk `path` (slash-separated), find-or-create each segment as a child doc.

    Uses find_document_with_retry() at each step so the matrix-parallel
    duplicate-folder bug is contained even when multiple shards walk the
    same path simultaneously.
    """
    if not path:
        return None

    parts = [p.strip() for p in path.split('/') if p.strip()]
    current_parent_id = None

    for part in parts:
        doc_id = find_document_with_retry(api_key, base_url, collection_id, part, current_parent_id)
        if not doc_id:
            print(f"Creating folder document: {part}")
            doc_id = create_document(
                api_key, base_url, collection_id, part, current_parent_id,
                text=f"# {part}\n\nFolder for reports.",
            )
        else:
            print(f"Found existing folder: {part}")
        current_parent_id = doc_id

    return current_parent_id


# -----------------------------------------------------------------------------
# Path / identifier helpers
# -----------------------------------------------------------------------------

_SLUG_STRIP_RE = re.compile(r'[^a-z0-9_-]+')


def slug(s):
    """Lowercase, replace any non-[a-z0-9_-] with `-`, collapse and trim dashes.

    Used to derive folder names from short codes and component names. The
    underscore is preserved so `_infra` (the infra-scan bucket convention)
    survives slugification.
    """
    if not s:
        return ''
    s = s.lower().strip()
    s = _SLUG_STRIP_RE.sub('-', s)
    s = re.sub(r'-+', '-', s).strip('-')
    return s


def short_sha(sha):
    """First 7 chars of a commit sha, lowercased. Empty input → 'unknown'."""
    if not sha:
        return 'unknown'
    return sha.strip().lower()[:7]


def resolve_commit_sha(arg_value):
    """Pick the commit SHA from explicit --commit-sha arg or GITHUB_SHA env.

    Returns 'unknown' if neither is set so the script doesn't hard-fail on
    local invocations. Callers that want strict-mode should validate before
    invoking.
    """
    if arg_value:
        return arg_value
    env = os.environ.get('GITHUB_SHA') or os.environ.get('COMMIT_SHA')
    if env:
        return env
    return 'unknown'


def compute_new_layout_paths(short_code, component, commit_sha):
    """Derive the (latest_parent_path, latest_title, history_parent_path,
    history_title) tuple for the new layout mode.

    Layout reminder:
        reports/ci/<short-code-lower>/<component>/latest
        reports/ci/<short-code-lower>/<component>/history/<YYYY-MM-DD>-<sha7>
    """
    sc_slug = slug(short_code)
    comp_slug = slug(component) or 'app'
    date_str = localized_timestamp(HISTORY_DATE_FORMAT)
    sha7 = short_sha(commit_sha)

    latest_parent_path = f"reports/ci/{sc_slug}/{comp_slug}"
    history_parent_path = f"{latest_parent_path}/history"
    latest_title = "latest"
    history_title = f"{date_str}-{sha7}" if sha7 != 'unknown' else date_str

    return latest_parent_path, latest_title, history_parent_path, history_title


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def _build_arg_parser():
    parser = argparse.ArgumentParser(description='Upload security reports to Outline')
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--collection-id', required=True)
    parser.add_argument('--report-files', required=True)
    parser.add_argument('--job-url', required=False, default='')
    # New-layout mode inputs.
    parser.add_argument('--short-code', required=False, default='',
                        help="App short code (e.g. NTH-AXT-FL-WA). Empty → legacy publish-path mode.")
    parser.add_argument('--component', required=False, default='app',
                        help="Sub-app component (matrix.component). Use 'app' for single-image apps.")
    parser.add_argument('--retention-count', type=int, required=False, default=100,
                        help="History docs to keep per (app, component) before archiving oldest.")
    parser.add_argument('--commit-sha', required=False, default='',
                        help="Commit SHA for history doc naming. Falls back to $GITHUB_SHA.")
    parser.add_argument('--dry-run', action='store_true',
                        help="Print resolved paths and exit without calling Outline.")
    # Legacy mode inputs (kept for backward compat).
    parser.add_argument('--publish-path', required=False, default='',
                        help="DEPRECATED: legacy path-based upload. Use --short-code + --component instead.")
    parser.add_argument('--project-name', required=False, default='',
                        help="Project name displayed in document body.")
    return parser


def main():
    args = _build_arg_parser().parse_args()

    api_key = os.environ.get('OUTLINE_API_KEY')
    if not api_key:
        raise SystemExit("OUTLINE_API_KEY environment variable is required")

    # --- Parse scan reports -----------------------------------------------------
    all_findings = []
    patterns = args.report_files.split(',')
    collection_id = args.collection_id.strip()

    for pattern in patterns:
        for file_path in glob.glob(pattern.strip()):
            print(f"Processing {file_path}...")
            if 'checkov' in file_path.lower():
                all_findings.extend(parse_checkov(file_path))
            elif 'trivy' in file_path.lower():
                all_findings.extend(parse_trivy(file_path))

    commit_sha = resolve_commit_sha(args.commit_sha)

    markdown_content = generate_markdown(
        all_findings,
        args.job_url,
        project_name=args.project_name or None,
        short_code=args.short_code or None,
        component=args.component or None,
        commit_sha=commit_sha if commit_sha != 'unknown' else None,
    )

    # --- Mode dispatch ----------------------------------------------------------
    if args.short_code:
        _run_new_layout(args, api_key, collection_id, commit_sha, markdown_content)
    elif args.publish_path:
        print("WARNING: --publish-path is deprecated. Migrate to --short-code + --component before v2.0.")
        _run_legacy(args, api_key, collection_id, markdown_content)
    else:
        # No path given → upload to collection root (matches v1.1.1 behaviour).
        _run_legacy(args, api_key, collection_id, markdown_content)


def _run_new_layout(args, api_key, collection_id, commit_sha, markdown_content):
    """New short-code/component layout with UPDATE-or-CREATE + retention."""
    latest_parent_path, latest_title, history_parent_path, history_title = compute_new_layout_paths(
        args.short_code, args.component, commit_sha,
    )

    print(f"New-layout mode:")
    print(f"  short-code  = {args.short_code} → slug '{slug(args.short_code)}'")
    print(f"  component   = {args.component}")
    print(f"  commit-sha  = {commit_sha} → short '{short_sha(commit_sha)}'")
    print(f"  latest path = {latest_parent_path}/{latest_title}")
    print(f"  history path= {history_parent_path}/{history_title}")
    print(f"  retention   = keep {args.retention_count}")

    if args.dry_run:
        print("DRY RUN — no API calls.")
        return

    # 1. Ensure the latest_parent path exists (this also creates the chain).
    print(f"Ensuring path: {latest_parent_path}")
    latest_parent_id = ensure_path(api_key, args.base_url, collection_id, latest_parent_path)

    # 2. UPDATE-or-CREATE the 'latest' doc.
    upsert_document(api_key, args.base_url, collection_id, latest_title, latest_parent_id, markdown_content)

    # 3. Ensure the history folder exists, then UPDATE-or-CREATE the history doc.
    #    Re-cuts of the same commit-day land in the same history doc (idempotent).
    print(f"Ensuring path: {history_parent_path}")
    history_parent_id = ensure_path(api_key, args.base_url, collection_id, history_parent_path)
    upsert_document(api_key, args.base_url, collection_id, history_title, history_parent_id, markdown_content)

    # 4. Retention — archive any docs beyond keep-N. Soft-fail.
    try:
        apply_retention(api_key, args.base_url, collection_id, history_parent_id, args.retention_count)
    except Exception as e:
        print(f"WARN: retention failed (non-fatal): {e}")

    print("✅ New-layout upload complete.")


def _run_legacy(args, api_key, collection_id, markdown_content):
    """Pre-v1.2 behaviour: walk publish-path, CREATE a timestamped doc.

    Kept verbatim from v1.1.1 for callers that haven't migrated. Will be
    removed in v2.0 once every consumer flips to --short-code + --component.
    """
    parent_doc_id = None
    if args.publish_path:
        print(f"Ensuring path structure: {args.publish_path}")
        try:
            parent_doc_id = ensure_path(api_key, args.base_url, collection_id, args.publish_path)
            print(f"Resolved parent document ID: {parent_doc_id}")
        except Exception as e:
            print(f"Failed to resolve path: {e}. Falling back to root.")

    title = f"Scan: {localized_timestamp(TITLE_TIMESTAMP_FORMAT)}"
    print(f"Uploading report '{title}'...")
    create_document(api_key, args.base_url, collection_id, title, parent_doc_id, markdown_content)
    print("✅ Legacy upload complete.")


if __name__ == "__main__":
    main()
