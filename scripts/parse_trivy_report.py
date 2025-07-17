# scripts/parse_trivy_report.py
import json
import sys

def parse_trivy_report(report_path):
    """
    Parses a Trivy JSON report to identify high/critical fixable vulnerabilities.
    """
    try:
        with open(report_path, 'r') as f:
            report_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Report file not found at {report_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {report_path}", file=sys.stderr)
        sys.exit(1)

    vulnerabilities = []
    
    # Trivy reports can have multiple results sections (e.g., OS, libraries, language-specific)
    for result in report_data.get('Results', []):
        target = result.get('Target') # e.g., "alpine:3.18", "/app/my-go-app"
        type_ = result.get('Type') # e.g., "alpine", "go-module", "java-archive"

        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN')
            fix_version = vuln.get('FixedVersion')
            installed_version = vuln.get('InstalledVersion')
            package_name = vuln.get('PkgName')
            vulnerability_id = vuln.get('VulnerabilityID')
            description = vuln.get('Description', 'No description available.')

            # We only care about high/critical vulnerabilities that have a fix version
            if severity in ['CRITICAL', 'HIGH'] and fix_version:
                vulnerabilities.append({
                    'VulnerabilityID': vulnerability_id,
                    'Severity': severity,
                    'PkgName': package_name,
                    'InstalledVersion': installed_version,
                    'FixedVersion': fix_version,
                    'Target': target,
                    'Type': type_,
                    'Description': description
                })

    # Sort by severity (Critical first)
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    vulnerabilities.sort(key=lambda x: severity_order.get(x['Severity'], 4))

    if vulnerabilities:
        print(f"Found {len(vulnerabilities)} fixable CRITICAL/HIGH vulnerabilities.")
        with open('vulnerabilities.json', 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
    else:
        print("No fixable CRITICAL/HIGH vulnerabilities found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse_trivy_report.py <trivy_report.json>", file=sys.stderr)
        sys.exit(1)
    report_file = sys.argv[1]
    parse_trivy_report(report_file)
