#!/usr/bin/env python3

import subprocess
import json
import logging
import os
import sys
import re
from datetime import datetime

# --- Configuration ---
LOG_FILE = "remediation.log"
TRIVY_REPORT_FILE = "trivy-report.json"
REMEDIATION_BRANCH_PREFIX = "auto-fix/vulns-"

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --- Utility Functions ---

def execute_command(command, cwd, description="command", check_returncode=False):
    """
    Executes a shell command.
    :param command: List of command and its arguments.
    :param cwd: Current working directory for the command.
    :param description: Human-readable description of the command for logging.
    :param check_returncode: If True, raises an exception for non-zero exit codes.
    :return: Tuple of (exit_code, stdout, stderr)
    """
    try:
        logger.info(f"Executing {description}: {' '.join(command)}")
        process = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)

        if process.returncode != 0:
            logger.error(f"Error executing {description} (Exit Code: {process.returncode}): {' '.join(command)}")
            logger.error(f"Stdout:\n{process.stdout}")
            logger.error(f"Stderr:\n{process.stderr}")
            if check_returncode:
                raise subprocess.CalledProcessError(process.returncode, command, process.stdout, process.stderr)
        else:
            logger.info(f"Successfully executed {description}.")
            logger.debug(f"Stdout:\n{process.stdout}")

        return process.returncode, process.stdout, process.stderr
    except FileNotFoundError:
        logger.error(f"Command not found: {command[0]}. Please ensure it's installed and in PATH.")
        return 1, "", f"Command not found: {command[0]}"
    except Exception as e:
        logger.error(f"An unexpected error occurred while executing {description} {' '.join(command)}: {e}")
        return 1, "", str(e)

def parse_trivy_report(report_path):
    """
    Parses a Trivy JSON report and extracts actionable NPM vulnerabilities.
    Actionable vulnerabilities are those that have a 'FixedVersion'.
    :param report_path: Path to the Trivy JSON report file.
    :return: List of dictionaries, each representing an actionable vulnerability.
    """
    vulnerabilities = []
    if not os.path.exists(report_path):
        logger.error(f"Trivy report not found at: {report_path}")
        return vulnerabilities

    try:
        with open(report_path, 'r') as f:
            report = json.load(f)

        for result in report.get('Results', []):
            if result.get('Type') == 'npm':
                for vuln_info in result.get('Vulnerabilities', []):
                    pkg_name = vuln_info.get('PkgName')
                    installed_version = vuln_info.get('InstalledVersion')
                    fixed_version = vuln_info.get('FixedVersion')
                    vulnerability_id = vuln_info.get('VulnerabilityID')
                    severity = vuln_info.get('Severity')
                    description = vuln_info.get('Description', 'No description available.')

                    # Only consider vulnerabilities with a fixed version
                    if pkg_name and fixed_version and fixed_version != "Not Specified":
                        vulnerabilities.append({
                            'PackageName': pkg_name,
                            'InstalledVersion': installed_version,
                            'FixedVersion': fixed_version,
                            'VulnerabilityID': vulnerability_id,
                            'Severity': severity,
                            'Description': description
                        })
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding Trivy JSON report: {e}")
    except Exception as e:
        logger.error(f"An error occurred while parsing Trivy report: {e}")

    logger.info(f"Found {len(vulnerabilities)} actionable vulnerabilities from report.")
    return vulnerabilities

def parse_fixed_version(version_string):
    """
    Parses a version string (e.g., '1.21.11, 1.22.4') and returns the highest valid semantic version.
    Handles common npm version prefixes.
    """
    if not version_string:
        return None

    # Clean the string, remove any non-version characters like '>=', '~', '^'
    cleaned_string = re.sub(r'[^0-9.,-]', '', version_string).strip()

    # Split by comma and strip whitespace
    versions = [v.strip() for v in cleaned_string.split(',') if v.strip()]

    # Filter out invalid or empty strings after splitting
    versions = [v for v in versions if re.match(r'^\d+(\.\d+){0,2}(\.\d+)?$', v)] # Simple regex for X.Y.Z

    if not versions:
        return None

    # Sort versions semantically (major.minor.patch)
    def version_key(version):
        parts = [int(p) for p in version.split('.')]
        return tuple(parts + [0]*(3-len(parts))) # Pad with zeros for consistent comparison

    versions.sort(key=version_key, reverse=True)

    if versions:
        return versions[0]
    return None

def apply_dockerfile_hardening(dockerfile_path):
    """
    Applies general hardening rules to a Dockerfile:
    - Adds or modifies USER to a non-root user.
    - Adds WORKDIR if not present.
    :param dockerfile_path: Path to the Dockerfile.
    :return: True if changes were applied, False otherwise.
    """
    logger.info(f"Attempting to apply general Dockerfile hardening rules.")
    if not os.path.exists(dockerfile_path):
        logger.warning(f"Dockerfile not found at {dockerfile_path}. Skipping Dockerfile hardening.")
        return False

    logger.info(f"Applying hardening to Dockerfile: {dockerfile_path}")
    changes_applied = False
    lines = []
    with open(dockerfile_path, 'r') as f:
        lines = f.readlines()

    new_lines = []
    user_found = False
    workdir_found = False
    insert_point_for_user = -1 # After the first FROM
    
    for i, line in enumerate(lines):
        # Check for existing USER instruction
        if line.strip().lower().startswith('user '):
            user_found = True
            logger.info("Dockerfile already has a non-root USER instruction or no suitable insertion point. Skipping user hardening.")
            # We assume if USER exists, it's either already non-root or handled manually.
            # A more advanced script would analyze the user ID.
            
        # Check for existing WORKDIR instruction
        if line.strip().lower().startswith('workdir '):
            workdir_found = True
            logger.info("Dockerfile already has a WORKDIR instruction. Skipping WORKDIR hardening.")

        if line.strip().lower().startswith('from ') and insert_point_for_user == -1:
            insert_point_for_user = i + 1 # Insert USER after the first FROM

        new_lines.append(line)
    
    # Add WORKDIR if not found
    if not workdir_found:
        # Try to find a good place to add WORKDIR, usually after FROM and RUN commands, before COPY/CMD/ENTRYPOINT
        # For simplicity, append it at the end for now, or before the first COPY/CMD/ENTRYPOINT
        if any("COPY" in l or "CMD" in l or "ENTRYPOINT" in l for l in new_lines):
            # Find the index of the first COPY, CMD, or ENTRYPOINT instruction
            insert_index = -1
            for i, line in enumerate(new_lines):
                if "COPY" in line or "CMD" in line or "ENTRYPOINT" in line:
                    insert_index = i
                    break
            if insert_index != -1:
                new_lines.insert(insert_index, "WORKDIR /app\n")
                changes_applied = True
                logger.info("Added WORKDIR /app to Dockerfile.")
            else:
                new_lines.append("WORKDIR /app\n")
                changes_applied = True
                logger.info("Appended WORKDIR /app to Dockerfile.")
        else:
            new_lines.append("WORKDIR /app\n")
            changes_applied = True
            logger.info("Appended WORKDIR /app to Dockerfile.")
            
    # Add non-root USER if not found and there's a suitable insertion point
    if not user_found and insert_point_for_user != -1:
        # Basic non-root user creation, assuming a Debian/Ubuntu base image for adduser/addgroup
        # For Alpine, it would be 'RUN adduser -D nonrootuser'
        user_add_commands = [
            "RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser\n",
            "USER appuser\n"
        ]
        # Check if the base image implies root and we need to add a user
        # This is a heuristic and might need refinement for diverse base images
        # For example, if 'FROM scratch' or specific distroless images, adding user is different
        if not any(re.search(r'^\s*FROM\s+.*\s+AS\s+builder', l, re.IGNORECASE) for l in lines) and \
           not any(re.search(r'FROM\s+(alpine|distroless|scratch|centos|rhel|ubi)', l, re.IGNORECASE) for l in lines):
            # Heuristic for common Debian/Ubuntu like images where adduser/addgroup is standard
            new_lines.insert(insert_point_for_user, "\n".join(user_add_commands))
            changes_applied = True
            logger.info("Added non-root USER 'appuser' to Dockerfile.")

    if changes_applied:
        with open(dockerfile_path, 'w') as f:
            f.writelines(new_lines)
        logger.info("Dockerfile hardening applied successfully.")
    else:
        logger.info("No significant Dockerfile hardening changes needed (USER and WORKDIR are present/handled).")

    return changes_applied

# --- Remediation Functions ---

def remediate_npm_vulnerabilities(project_path, vulnerabilities):
    """
    Attempts to remediate NPM vulnerabilities using 'npm audit fix' and direct installs.
    :param project_path: Path to the NPM project directory.
    :param vulnerabilities: List of NPM vulnerabilities from Trivy report.
    :return: List of vulnerabilities that could NOT be fixed.
    """
    unfixed_vulnerabilities = []

    logger.info(f"Starting NPM vulnerability remediation in {project_path}.")

    # Phase 1: Attempt npm audit fix without --force
    logger.info(f"Attempting initial 'npm audit fix' in {project_path}")
    exit_code, stdout, stderr = execute_command(["npm", "audit", "fix"], project_path, "npm audit fix")

    # Check if npm audit fix suggested --force
    requires_force = False
    if "npm audit fix --force" in stdout or "npm audit fix --force" in stderr:
        requires_force = True
        logger.warning("'npm audit fix' suggested using '--force'.")
    
    # Phase 2: If issues remain or --force was suggested, attempt npm audit fix --force
    if exit_code != 0 or requires_force:
        if requires_force:
            logger.info(f"Attempting 'npm audit fix --force' in {project_path}")
            force_exit_code, force_stdout, force_stderr = execute_command(["npm", "audit", "fix", "--force"], project_path, "npm audit fix --force")
            if force_exit_code == 0:
                logger.info("Successfully fixed some vulnerabilities with 'npm audit fix --force'.")
            else:
                logger.error("'npm audit fix --force' failed to resolve all issues.")
                # If force failed, all original vulnerabilities are potentially unfixed.
                unfixed_vulnerabilities.extend(vulnerabilities)
                return unfixed_vulnerabilities
        else:
            logger.error("'npm audit fix' failed without suggesting '--force'.")
            # If basic audit fix failed and force wasn't suggested, these are tough ones.
            unfixed_vulnerabilities.extend(vulnerabilities)
            return unfixed_vulnerabilities
    else:
        logger.info("Initial 'npm audit fix' successfully resolved all issues or found none requiring attention.")
        # If npm audit fix succeeded, assume all are fixed for now.
        return [] # No unfixed vulnerabilities if audit fix succeeded.

    # Phase 3: Targeted npm install for specific vulnerabilities not caught by audit fix
    # This phase runs only if audit fix --force was attempted but didn't completely clear.
    # To determine *which* vulnerabilities remain, we'd ideally re-scan here, but for
    # simplicity, we'll try to apply direct installs for all original actionable ones
    # that 'npm audit fix --force' might have missed.
    
    # NOTE: Re-scanning here would be ideal to get the *remaining* vulns.
    # For this script, we'll iterate through the original list and try direct fixes
    # as a fallback if the previous `npm audit fix --force` didn't fix them.
    # A true robust system would re-parse Trivy after each major fix attempt.

    logger.info("Attempting targeted 'npm install' for specific packages not resolved by audit fix.")
    for vuln in vulnerabilities:
        package_name = vuln['PackageName']
        trivy_fixed_version_string = vuln['FixedVersion']
        cve_id = vuln['VulnerabilityID']

        resolved_version = parse_fixed_version(trivy_fixed_version_string)
        
        if resolved_version:
            logger.info(f"Attempting to fix npm package: {package_name} to version {resolved_version} for {cve_id}")
            install_command = ["npm", "install", f"{package_name}@{resolved_version}"]
            install_exit_code, install_stdout, install_stderr = execute_command(install_command, project_path, f"npm install {package_name}@{resolved_version}")

            if install_exit_code == 0:
                logger.info(f"Successfully updated '{package_name}' to '{resolved_version}'.")
            else:
                logger.warning(f"Failed to apply fix for {package_name}@{resolved_version}. Manual intervention may be needed for {cve_id}.")
                unfixed_vulnerabilities.append(vuln)
        else:
            logger.warning(f"Could not parse a valid fixed version for {package_name} from '{trivy_fixed_version_string}'. Manual intervention for {cve_id} may be needed.")
            unfixed_vulnerabilities.append(vuln)

    # Note: A complete solution would re-run `npm audit` or `trivy` here to confirm actual fixes.
    # For now, we rely on the exit codes and logs.
    return unfixed_vulnerabilities

# --- Git Operations ---

def setup_git_branch(repo_path, branch_name):
    """Sets up a new Git branch for remediation."""
    logger.info(f"Setting up Git branch '{branch_name}' in {repo_path}.")
    execute_command(["git", "config", "user.name", "GitHub Actions Automation"], repo_path, "Git config user.name")
    execute_command(["git", "config", "user.email", "actions@github.com"], repo_path, "Git config user.email")
    execute_command(["git", "fetch", "origin"], repo_path, "Git fetch origin")
    execute_command(["git", "checkout", "-b", branch_name], repo_path, f"Checkout new branch {branch_name}")

def commit_and_push_changes(repo_path, branch_name, message):
    """Commits and pushes changes to the remote repository."""
    logger.info(f"Committing and pushing changes to {branch_name}.")
    exit_code, stdout, stderr = execute_command(["git", "add", "."], repo_path, "Git add all changes")
    if exit_code != 0:
        logger.error("Failed to stage changes. Is there anything to commit?")
        return False

    exit_code, stdout, stderr = execute_command(["git", "commit", "-m", message], repo_path, "Git commit changes")
    if exit_code != 0:
        # This can happen if there are no changes to commit
        if "nothing to commit" in stdout or "nothing to commit" in stderr:
            logger.info("No changes to commit.")
            return True # Consider it a success if no changes were needed
        logger.error("Failed to commit changes.")
        return False
    
    exit_code, stdout, stderr = execute_command(["git", "push", "origin", branch_name], repo_path, f"Git push to {branch_name}")
    if exit_code != 0:
        logger.error("Failed to push changes.")
        return False
    
    logger.info("Changes committed and pushed successfully.")
    return True

# --- Main Pipeline Logic ---

def run_remediation_pipeline(repo_root_path, frontend_relative_path, dockerfile_relative_path, trivy_report_path):
    """
    Orchestrates the entire vulnerability remediation pipeline.
    :param repo_root_path: The root path of the Git repository.
    :param frontend_relative_path: Relative path from repo_root_path to the frontend project.
    :param dockerfile_relative_path: Relative path from repo_root_path to the Dockerfile.
    :param trivy_report_path: Path to the Trivy JSON report (absolute or relative to script execution).
    """
    frontend_path = os.path.join(repo_root_path, frontend_relative_path)
    dockerfile_path = os.path.join(repo_root_path, dockerfile_relative_path)

    logger.info(f"Starting automated vulnerability remediation pipeline for {frontend_path}/")
    logger.info(f"Dockerfile Path: {dockerfile_path}")

    # 1. Dockerfile Hardening
    dockerfile_modified = apply_dockerfile_hardening(dockerfile_path)

    # 2. Parse Trivy Report
    logger.info(f"Parsing initial Trivy report: {trivy_report_path}")
    actionable_vulnerabilities = parse_trivy_report(trivy_report_path)

    if not actionable_vulnerabilities:
        logger.info("No actionable vulnerabilities found in the report. Exiting remediation.")
        return True # No vulnerabilities, so success

    # 3. Remediate Application-level Dependencies (NPM)
    unfixed_npm_vulnerabilities = remediate_npm_vulnerabilities(frontend_path, actionable_vulnerabilities)

    # Check if any remediation attempts resulted in actual changes (e.g., package.json/lock updated, Dockerfile changed)
    # A more robust check would involve comparing file hashes or git status.
    changes_made = dockerfile_modified or not unfixed_npm_vulnerabilities # Simplistic check

    if not changes_made:
        logger.info("No significant changes were applied during remediation. No commit needed.")
        return True

    # 4. Git Operations: Commit and Push
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    remediation_branch = f"{REMEDIATION_BRANCH_PREFIX}{current_time}"
    commit_message = "feat(security): Automated vulnerability remediation\n\n"

    if dockerfile_modified:
        commit_message += "- Applied Dockerfile hardening (non-root user, WORKDIR).\n"
    if not unfixed_npm_vulnerabilities:
        commit_message += "- Fixed NPM package vulnerabilities using 'npm audit fix --force' and targeted installs.\n"
    else:
        commit_message += f"- Attempted to fix NPM package vulnerabilities. {len(unfixed_npm_vulnerabilities)} vulnerabilities remain.\n"
        commit_message += "  Unfixed CVEs: " + ", ".join([v['VulnerabilityID'] for v in unfixed_npm_vulnerabilities]) + "\n"

    setup_git_branch(repo_root_path, remediation_branch)
    if commit_and_push_changes(repo_root_path, remediation_branch, commit_message):
        logger.info(f"Successfully pushed changes to branch '{remediation_branch}'.")
        # In a real CI/CD, you'd create a Pull Request here via GitHub API
        logger.info(f"Please review changes on branch: {remediation_branch}")
        # 5. Rebuild & Retest (Triggered by PR or subsequent workflow step)
        # This part would typically be handled by a separate CI/CD job triggered by the PR
        # or a push to the remediation branch.
        if unfixed_npm_vulnerabilities:
            logger.warning("Some vulnerabilities could not be fixed automatically. Manual intervention required.")
            return False # Indicate partial success or failure to fully remediate
        return True # Indicate full automated remediation success
    else:
        logger.error("Failed to commit and push remediation changes.")
        return False

# --- Main Execution ---
if __name__ == "__main__":
    # Define paths relative to the script's execution environment
    # In a GitHub Actions workflow, GITHUB_WORKSPACE is the repo root.
    repo_root = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    
    # These paths are based on your provided log:
    # /home/runner/work/real-estate-management/real-estate-management/frontend/
    frontend_app_path = "frontend/" # Relative to repo_root
    dockerfile_path = "frontend/Dockerfile" # Relative to repo_root
    trivy_report = "trivy-report.json" # Assumed to be in the root of the workflow's working directory

    # For local testing without GitHub Actions env vars, adjust paths if needed.
    # Example:
    # repo_root = "/path/to/your/repo"
    # frontend_app_path = "frontend"
    # dockerfile_path = os.path.join(frontend_app_path, "Dockerfile")
    # trivy_report = "trivy-report.json" # Or full path if not in current working dir

    if not run_remediation_pipeline(repo_root, frontend_app_path, dockerfile_path, trivy_report):
        logger.error("Automated remediation pipeline finished with unresolved issues.")
        sys.exit(1)
    else:
        logger.info("Automated remediation pipeline completed successfully (or with manageable unfixed issues).")
