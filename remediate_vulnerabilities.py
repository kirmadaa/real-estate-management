import json
import os
import subprocess
import re
from datetime import datetime

TRIVY_REPORT_PATH = "trivy-report.json"
REMEDIATION_BRANCH_PREFIX = "security/auto-remediate-"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

def send_slack_notification(message):
    if not SLACK_WEBHOOK_URL:
        print("Slack webhook URL not configured. Skipping notification.")
        return
    try:
        import requests
        headers = {'Content-type': 'application/json'}
        payload = json.dumps({"text": message})
        response = requests.post(SLACK_WEBHOOK_URL, headers=headers, data=payload)
        response.raise_for_status()
        print(f"Slack notification sent: {message}")
    except Exception as e:
        print(f"Failed to send Slack notification: {e}")

def parse_trivy_report():
    if not os.path.exists(TRIVY_REPORT_PATH):
        print(f"Error: Trivy report not found at {TRIVY_REPORT_PATH}")
        return []

    with open(TRIVY_REPORT_PATH, 'r') as f:
        report = json.load(f)

    vulnerabilities = []
    for result in report.get('Results', []):
        target = result.get('Target')
        for vuln in result.get('Vulnerabilities', []):
            if vuln.get('Severity') in ['CRITICAL', 'HIGH'] and vuln.get('FixedVersion'):
                vulnerabilities.append({
                    'target': target,
                    'vulnerability_id': vuln.get('VulnerabilityID'),
                    'severity': vuln.get('Severity'),
                    'package_name': vuln.get('PkgName'),
                    'installed_version': vuln.get('InstalledVersion'),
                    'fixed_version': vuln.get('FixedVersion'),
                    'description': vuln.get('Description'),
                    'primary_url': vuln.get('PrimaryURL')
                })
    return vulnerabilities

def update_python_requirements(package_name, fixed_version):
    requirements_path = "requirements.txt"
    if not os.path.exists(requirements_path):
        print(f"requirements.txt not found. Cannot update {package_name}.")
        return False

    original_content = ""
    with open(requirements_path, 'r') as f:
        original_content = f.read()

    new_content = []
    updated = False
    for line in original_content.splitlines():
        # Use regex to find package name, ignoring comments and potential extra spaces
        match = re.match(r'^\s*([a-zA-Z0-9_\-]+)(==|>=|<=|~=|<|>|!=\s*)?.*', line)
        if match:
            pkg = match.group(1).strip()
            if pkg.lower() == package_name.lower():
                # Update the version or add if only package name exists
                if '==' in line or '>=' in line or '<=' in line or '~=' in line:
                    new_line = f"{pkg}=={fixed_version}"
                    print(f"Updating '{line.strip()}' to '{new_line}' in {requirements_path}")
                else:
                    new_line = f"{pkg}=={fixed_version}"
                    print(f"Adding/Updating '{pkg}' to '{new_line}' in {requirements_path}")
                new_content.append(new_line)
                updated = True
                continue
        new_content.append(line)

    if updated:
        with open(requirements_path, 'w') as f:
            f.write("\n".join(new_content))
        print(f"Successfully updated {package_name} to {fixed_version} in {requirements.txt}")
        return True
    else:
        print(f"Could not find or update {package_name} in {requirements_path}. Attempting to append.")
        # If not found, append it if it's a direct dependency that needs fixing
        with open(requirements_path, 'a') as f:
            f.write(f"\n{package_name}=={fixed_version}")
        print(f"Appended {package_name}=={fixed_version} to {requirements.txt}")
        return True # Assume appended is a fix attempt

    return False

def apply_remediation(vulnerability):
    pkg_name = vulnerability['package_name']
    fixed_version = vulnerability['fixed_version']
    target = vulnerability['target']

    if "python" in target.lower() and "requirements.txt" in target.lower():
        print(f"Attempting to remediate Python package: {pkg_name} to {fixed_version}")
        return update_python_requirements(pkg_name, fixed_version)
    elif "os" in target.lower() and "library" in target.lower():
        # For OS level packages, direct modification of Dockerfile for specific `RUN apt-get install`
        # is complex and specific. Best practice is to update the base image.
        # This part requires manual intervention or a more sophisticated Dockerfile parser.
        # For this demo, we'll focus on application dependencies.
        print(f"OS package remediation for {pkg_name} requires Dockerfile modification or base image update. Skipping automated fix.")
        return False
    else:
        print(f"Unsupported target type for automatic remediation: {target}")
        return False

def run_git_command(command, check_output=False):
    try:
        if check_output:
            return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.PIPE).strip()
        else:
            subprocess.check_call(command, shell=True, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Git command failed: {command}\nError: {e.stderr}")
        return False

def main():
    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN environment variable not set. Cannot perform Git operations.")
        send_slack_notification("Automated vulnerability remediation failed: GITHUB_TOKEN not set.")
        exit(1)

    vulnerabilities = parse_trivy_report()
    if not vulnerabilities:
        print("No high/critical vulnerabilities with fixed versions found. Exiting.")
        send_slack_notification("Automated vulnerability remediation completed: No high/critical vulnerabilities found with fixed versions.")
        exit(0)

    remediated_vulnerabilities = []
    for vuln in vulnerabilities:
        if apply_remediation(vuln):
            remediated_vulnerabilities.append(vuln)

    if not remediated_vulnerabilities:
        print("No vulnerabilities were successfully remediated by the script. Exiting.")
        send_slack_notification("Automated vulnerability remediation completed: No vulnerabilities could be automatically fixed.")
        exit(0)

    # Git operations
    current_branch = run_git_command("git rev-parse --abbrev-ref HEAD", check_output=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    new_branch_name = f"{REMEDIATION_BRANCH_PREFIX}{timestamp}"
    commit_message = "feat(security): Automated vulnerability remediation\n\n"
    pr_body = "This PR automatically remediates the following vulnerabilities:\n\n"

    for vuln in remediated_vulnerabilities:
        commit_message += f"- {vuln['vulnerability_id']} ({vuln['package_name']} {vuln['installed_version']} -> {vuln['fixed_version']})\n"
        pr_body += f"- **{vuln['vulnerability_id']}**: {vuln['package_name']} from {vuln['installed_version']} to {vuln['fixed_version']}\n"
        pr_body += f"  Severity: {vuln['severity']}\n"
        pr_body += f"  Description: {vuln['description'][:150]}...\n" # Truncate for brevity
        pr_body += f"  More info: {vuln['primary_url']}\n\n"

    run_git_command(f"git config user.name 'github-actions[bot]'")
    run_git_command(f"git config user.email 'github-actions[bot]@users.noreply.github.com'")

    if not run_git_command(f"git checkout -b {new_branch_name}"):
        send_slack_notification(f"Automated vulnerability remediation failed: Could not create new branch {new_branch_name}.")
        exit(1)

    if not run_git_command("git add ."):
        send_slack_notification(f"Automated vulnerability remediation failed: Could not stage changes on branch {new_branch_name}.")
        exit(1)

    if not run_git_command(f'git commit -m "{commit_message}"'):
        send_slack_notification(f"Automated vulnerability remediation failed: Could not commit changes on branch {new_branch_name}.")
        exit(1)

    if not run_git_command(f"git push origin {new_branch_name}"):
        send_slack_notification(f"Automated vulnerability remediation failed: Could not push branch {new_branch_name}.")
        exit(1)

    # Create Pull Request
    repo_name = os.environ.get("GITHUB_REPOSITORY")
    if not repo_name:
        print("Error: GITHUB_REPOSITORY environment variable not set. Cannot create PR.")
        send_slack_notification("Automated vulnerability remediation failed: GITHUB_REPOSITORY not set.")
        exit(1)

    try:
        import requests
        pr_title = "Automated Security Remediation"
        pr_data = {
            "title": pr_title,
            "head": new_branch_name,
            "base": "main",
            "body": pr_body
        }
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        response = requests.post(
            f"https://api.github.com/repos/{repo_name}/pulls",
            headers=headers,
            data=json.dumps(pr_data)
        )
        response.raise_for_status()
        pr_info = response.json()
        pr_url = pr_info['html_url']
        print(f"Pull Request created: {pr_url}")
        send_slack_notification(f"Automated vulnerability remediation completed. Pull Request created: {pr_url}")

    except Exception as e:
        print(f"Failed to create Pull Request: {e}")
        send_slack_notification(f"Automated vulnerability remediation completed, but failed to create Pull Request: {e}")
        exit(1)

if __name__ == "__main__":
    main()
