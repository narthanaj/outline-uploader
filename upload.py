import os
import json
import argparse
import requests
import glob
import datetime

# Default report timestamps include timezone offset for clarity
REPORT_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M %z'
# Titles omit timezone offsets (e.g., +HHMM) to avoid special characters in document names
TITLE_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M'

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
    """
    Return the current time formatted as a string in the local timezone.
    A UTC timestamp is converted to the local zone to ensure offset data
    is present even if the host timezone is not fully configured. The
    default format includes the +HHMM offset unless overridden.
    """
    localized_now = datetime.datetime.now(datetime.timezone.utc).astimezone()
    return localized_now.strftime(format_string)

def generate_markdown(findings, job_url, project_name=None):
    timestamp_str = localized_timestamp()
    total_issues = len(findings)

    findings.sort(key=lambda x: get_severity_weight(x['severity']))

    severity_counts = {}
    for f in findings:
        sev = f['severity'].upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    md = f"# 🛡️ Security Scan Report\n\n"
    if project_name:
        md += f"**Project**: {project_name}  \n"
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
        
        # Using standard Markdown as Outline sanitized the HTML details/summary tags
        md += f"#### [{f['tool']}] {f['id']}: {desc[:80]}...\n\n"
        md += f"- **Resource**: `{resource}`\n"
        md += f"- **File**: `{f['file']}`\n"
        if f.get('fixed_version') and f['fixed_version'] != 'N/A':
             md += f"- **Fixed Version**: `{f['fixed_version']}`\n"
        
        md += f"\n> {desc}\n\n"

    md += "---\n*Report generated by Outline Uploader Action*"
    return md

def headers(api_key):
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

def find_document(api_key, base_url, collection_id, title, parent_id=None):
    url = f"{base_url.rstrip('/')}/api/documents.search"
    payload = {
        "collectionId": collection_id,
        "query": title,
        "includeArchived": False,
        "limit": 10
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

def create_document(api_key, base_url, collection_id, title, parent_id=None, text=""):
    url = f"{base_url.rstrip('/')}/api/documents.create"
    payload = {
        "collectionId": collection_id,
        "title": title,
        "text": text,
        "publish": True
    }
    if parent_id:
        payload["parentDocumentId"] = parent_id
    
    response = requests.post(url, headers=headers(api_key), json=payload)
    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        raise Exception(f"Failed to create document '{title}': {response.text}")

def ensure_path(api_key, base_url, collection_id, path):
    if not path:
        return None
        
    parts = [p.strip() for p in path.split('/') if p.strip()]
    current_parent_id = None
    
    for part in parts:
        doc_id = find_document(api_key, base_url, collection_id, part, current_parent_id)
        
        if not doc_id:
            print(f"Creating folder document: {part}")
            doc_id = create_document(api_key, base_url, collection_id, part, current_parent_id, text=f"# {part}\n\nFolder for reports.")
        else:
            print(f"Found existing folder: {part}")
            
        current_parent_id = doc_id
        
    return current_parent_id

def main():
    parser = argparse.ArgumentParser(description='Upload security reports to Outline')
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--collection-id', required=True)
    parser.add_argument('--report-files', required=True)
    parser.add_argument('--job-url', required=False)
    parser.add_argument('--publish-path', required=False, default='', help="Path like 'Reports/CI/K8s'")
    parser.add_argument('--project-name', required=False, default='', help="Project name for report header")

    args = parser.parse_args()

    api_key = os.environ.get('OUTLINE_API_KEY')
    if not api_key:
        raise SystemExit("OUTLINE_API_KEY environment variable is required")

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

    markdown_content = generate_markdown(all_findings, args.job_url, args.project_name or None)
    
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
    print("✅ Upload complete.")

if __name__ == "__main__":
    main()
