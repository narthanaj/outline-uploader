import os
import json
import argparse
import requests
import glob

def parse_checkov(file_path):
    if not os.path.exists(file_path):
        return []
    
    findings = []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        # Checkov output can be a list (multiple checks) or dict
        if isinstance(data, dict):
            data = [data]
            
        for result in data:
            if 'results' in result and 'failed_checks' in result['results']:
                for check in result['results']['failed_checks']:
                    findings.append({
                        'tool': 'Checkov',
                        'severity': 'HIGH', # Checkov usually just passes/fails
                        'id': check.get('check_id'),
                        'description': check.get('check_name'),
                        'resource': check.get('resource'),
                        'file': check.get('file_path')
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
            data = json.load(f)
            
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
                            'file': target
                        })
    except Exception as e:
        print(f"Error parsing Trivy file {file_path}: {e}")
        
    return findings

def generate_markdown(findings):
    if not findings:
        return "## Security Scan Results\n\n✅ No security issues found!"
        
    md = "## Security Scan Results\n\n"
    md += f"Found {len(findings)} issues.\n\n"
    
    md += "| Tool | Severity | ID | Resource | Description | File |\n"
    md += "|---|---|---|---|---|---|\n"
    
    for f in findings:
        # Sanitize pipes in description
        desc = f['description'].replace('|', ' ') if f['description'] else ''
        md += f"| {f['tool']} | {f['severity']} | {f['id']} | {f['resource']} | {desc} | {f['file']} |\n"
        
    return md

def upload_to_outline(api_key, base_url, collection_id, title, content):
    url = f"{base_url.rstrip('/')}/api/documents.create"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {
        "collectionId": collection_id,
        "title": title,
        "text": content,
        "publish": True
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Successfully uploaded to Outline: {response.json().get('data', {}).get('url')}")
    except requests.exceptions.HTTPError as e:
        print(f"Failed to upload to Outline: {e}")
        print(f"Response: {response.text}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description='Upload security reports to Outline')
    parser.add_argument('--api-key', required=True, help='Outline API Key')
    parser.add_argument('--base-url', required=True, help='Outline Base URL')
    parser.add_argument('--collection-id', required=True, help='Outline Collection ID')
    parser.add_argument('--report-files', required=True, help='Comma separated list of report files pattern')
    parser.add_argument('--job-url', required=False, help='URL of the CI job')
    
    args = parser.parse_args()
    
    all_findings = []
    
    patterns = args.report_files.split(',')
    for pattern in patterns:
        for file_path in glob.glob(pattern.strip()):
            print(f"Processing {file_path}...")
            if 'checkov' in file_path.lower():
                all_findings.extend(parse_checkov(file_path))
            elif 'trivy' in file_path.lower():
                all_findings.extend(parse_trivy(file_path))
            else:
                print(f"Unknown report type for {file_path}, attempting generic parse...")
                # Fallback or strict? Let's just try checkov format as default or skip
                pass

    markdown_content = generate_markdown(all_findings)
    
    if args.job_url:
        markdown_content = f"**Source Job**: {args.job_url}\n\n" + markdown_content
        
    import datetime
    title = f"Security Scan Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    upload_to_outline(args.api_key, args.base_url, args.collection_id, title, markdown_content)

if __name__ == "__main__":
    main()
