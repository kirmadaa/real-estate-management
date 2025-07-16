import json
import os
import re
import subprocess
import sys
import logging
import tempfile
import time # For retry mechanism

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(cmd, cwd=None, check_result=True, capture_output=False, description="command"):
    """Helper to run shell commands with improved error handling and logging."""
    cmd_str = ' '.join(cmd)
    logging.info(f"Executing {description}: {cmd_str}")
    try:
        process = subprocess.run(cmd, cwd=cwd, check=False, # Set check=False to handle errors gracefully here
                                 capture_output=True, text=True, encoding='utf-8')

        if process.returncode != 0:
            logging.error(f"Error executing {description} (Exit Code: {process.returncode}): {cmd_str}")
            logging.error(f"Stdout:\n{process.stdout}")
            logging.error(f"Stderr:\n{process.stderr}")
            if check_result:
                # Raise the error so the calling function can catch it if check_result is True
                raise subprocess.CalledProcessError(process.returncode, cmd, output=process.stdout, stderr=process.stderr)
            return False, process.stderr # Return stderr for error analysis

        if capture_output:
            return True, process.stdout.strip()
        return True, None
    except FileNotFoundError:
        logging.error(f"Command not found: '{cmd[0]}'. Please ensure it's installed and in PATH.")
        if check_result:
            raise
        return False, "Command not found"
    except Exception as e:
        logging.error(f"An unexpected error occurred while executing {description} '{cmd_str}': {e}")
        if check_result:
            raise
        return False, str(e)

def atomic_write_file(filepath, content):
    """Writes content to a file atomically to prevent data corruption."""
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(content)
        os.replace(temp_file.name, filepath)
        logging.info(f"Successfully updated file: {filepath}")
        return True
    except Exception as e:
        logging.error(f"Failed to atomically write to {filepath}: {e}")
        # Clean up temp file if os.replace fails for some reason
        if os.path.exists(temp_file.name):
            os.remove(temp_file.name)
        return False

def update_dockerfile_base_image(dockerfile_path, current_image, fixed_image):
    """Updates the base image in a Dockerfile."""
    logging.info(f"Attempting to update base image in {dockerfile_path} from '{current_image}' to '{fixed_image}'")
    
    if not os.path.exists(dockerfile_path):
        logging.warning(f"Dockerfile '{dockerfile_path}' not found for update. Skipping.")
        return False

    try:
        with open(dockerfile_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = []
        updated = False
        for line in lines:
            # Use regex to match FROM, allowing for comments and multiple spaces
            # Ensure it captures the exact current image to avoid unintended replacements
            # This regex also handles 'FROM image:tag AS builder'
            from_pattern = r"^\s*FROM\s+(" + re.escape(current_image) + r")(\s+AS\s+\S+)?\s*(#.*)?$"
            match = re.match(from_pattern, line, re.IGNORECASE)
            if match:
                # Replace only the image part, preserve 'AS builder' and comments
                new_line = line.replace(match.group(1), fixed_image, 1)
                new_lines.append(new_line)
                logging.info(f"Updated FROM line: {new_line.strip()}")
                updated = True
            else:
                new_lines.append(line)

        if updated:
            return atomic_write_file(dockerfile_path, "".join(new_lines))
        else:
            logging.info(f"Could not find '{current_image}' in Dockerfile '{dockerfile_path}' to update (or it's already updated).")
            return False
    except Exception as e:
        logging.error(f"Error updating Dockerfile base image in '{dockerfile_path}': {e}")
        return False

# Placeholder functions for other package managers
# These would be enhanced to parse package files and update versions programmatically
def fix_npm_dependency(package_name, fixed_version, app_root_dir):
    """
    Fixes a specific NPM package dependency by running npm commands
    in the specified application root directory. Prioritizes 'npm audit fix'.
    If that doesn't fix it, attempts direct install.
    """
    logging.info(f"Attempting to fix NPM package '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    
    package_json_path = os.path.join(app_root_dir, 'package.json')
    if not os.path.exists(package_json_path):
        logging.warning(f"package.json not found at {package_json_path}. Skipping NPM fix for {package_name}.")
        return False

    # Try npm audit fix first
    logging.info(f"Running 'npm audit fix' in {app_root_dir}")
    success_audit, audit_output = run_command(["npm", "audit", "fix"], cwd=app_root_dir, check_result=False, capture_output=True, description="npm audit fix")
    if success_audit:
        logging.info(f"Successfully ran 'npm audit fix'. Verifying if fix was applied.")
        return True
    else:
        logging.warning(f"npm audit fix failed or didn't fully resolve for {package_name}. Trying npm install with fixed version: {fixed_version}.")
        try:
            install_cmd = ["npm", "install", f"{package_name}@{fixed_version}"]
            logging.info(f"Running '{' '.join(install_cmd)}' in {app_root_dir}")
            success_install, _ = run_command(install_cmd, cwd=app_root_dir, description="npm install")
            if success_install:
                logging.info(f"Successfully ran 'npm install {package_name}@{fixed_version}'.")
                return True
            else:
                logging.error(f"Failed to fix NPM package '{package_name}' with fixed version '{fixed_version}'.")
                return False
        except Exception as e:
            logging.error(f"An error occurred during npm install for {package_name}: {e}")
            return False

def fix_pip_dependency(package_name, fixed_version, app_root_dir):
    logging.info(f"Attempting to fix Python package '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    requirements_path = os.path.join(app_root_dir, 'requirements.txt')
    updated_requirements_file = False
    if os.path.exists(requirements_path):
        try:
            with open(requirements_path, 'r', encoding='utf-8') as f: lines = f.readlines()
            new_lines = []
            updated = False
            for line in lines:
                pkg_pattern = r"^\s*" + re.escape(package_name) + r"([<>=!~=]=?[\d\.]+.*)?$"
                if re.match(pkg_pattern, line, re.IGNORECASE):
                    if re.search(r"[<>=!~=]=?[\d\.]+", line):
                        new_line = re.sub(r"([<>=!~=]=?[\d\.]+)", f"=={fixed_version}", line, count=1)
                    else:
                        new_line = line.strip() + f"=={fixed_version}\n"
                    if new_line != line:
                        new_lines.append(new_line)
                        updated = True
                    else: new_lines.append(line)
                else: new_lines.append(line)
            if updated:
                if atomic_write_file(requirements_path, "".join(new_lines)): updated_requirements_file = True
                else: return False
        except Exception as e:
            logging.error(f"Error updating requirements.txt for {package_name}: {e}")
    if updated_requirements_file:
        success, _ = run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=app_root_dir, description="pip install -r requirements.txt")
        if success: return True
    success, _ = run_command([sys.executable, "-m", "pip", "install", "--upgrade", f"{package_name}=={fixed_version}"], cwd=app_root_dir, check_result=False, description="pip install upgrade")
    return success

def fix_gem_dependency(package_name, fixed_version, app_root_dir):
    logging.info(f"Attempting to fix Ruby gem '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    gemfile_path = os.path.join(app_root_dir, 'Gemfile')
    gemfile_lock_path = os.path.join(app_root_dir, 'Gemfile.lock')
    if not os.path.exists(gemfile_path) and not os.path.exists(gemfile_lock_path):
        logging.warning(f"Neither Gemfile nor Gemfile.lock found at {app_root_dir}. Skipping Ruby gem fix for {package_name}.")
        return False
    updated_gemfile = False
    if os.path.exists(gemfile_path):
        try:
            with open(gemfile_path, 'r', encoding='utf-8') as f: lines = f.readlines()
            new_lines = []
            updated = False
            for line in lines:
                gem_pattern = r"^\s*gem\s+['\"]" + re.escape(package_name) + r"['\"](\s*,.*)?$"
                match = re.match(gem_pattern, line, re.IGNORECASE)
                if match:
                    new_line = f"  gem '{package_name}', '~> {fixed_version}'\n"
                    if new_line.strip() != line.strip():
                        new_lines.append(new_line)
                        updated = True
                    else: new_lines.append(line)
                else: new_lines.append(line)
            if updated:
                if atomic_write_file(gemfile_path, "".join(new_lines)): updated_gemfile = True
                else: return False
        except Exception as e:
            logging.error(f"Error updating Gemfile for {package_name}: {e}")
    if updated_gemfile:
        success_bundle, _ = run_command(["bundle", "install"], cwd=app_root_dir, description="bundle install")
        if success_bundle: return True
    success, _ = run_command(["bundle", "update", package_name], cwd=app_root_dir, check_result=False, description="bundle update")
    if success: return True
    success_install, _ = run_command(["bundle", "install"], cwd=app_root_dir, check_result=False, description="bundle install")
    return success_install

def fix_go_dependency(package_name, fixed_version, app_root_dir):
    logging.info(f"Attempting to fix Go module '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    go_mod_path = os.path.join(app_root_dir, 'go.mod')
    if not os.path.exists(go_mod_path):
        logging.warning(f"go.mod not found at {go_mod_path}. Skipping Go module fix for {package_name}.")
        return False
    success_get, _ = run_command(["go", "get", f"{package_name}@{fixed_version}"], cwd=app_root_dir, check_result=False, description="go get")
    if success_get:
        success_tidy, _ = run_command(["go", "mod", "tidy"], cwd=app_root_dir, description="go mod tidy")
        return success_tidy
    return False

def harden_dockerfile(dockerfile_path):
    """
    Applies basic Dockerfile hardening:
    - Ensures a non-root user is used if not already.
    - Adds a WORKDIR if not present.
    """
    logging.info(f"Applying hardening to Dockerfile: {dockerfile_path}")
    
    if not os.path.exists(dockerfile_path):
        logging.warning(f"Dockerfile '{dockerfile_path}' not found for hardening. Skipping.")
        return False

    try:
        with open(dockerfile_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = list(lines) # Create a mutable copy
        user_set_explicitly = False
        workdir_set = False
        
        # Check for existing USER and WORKDIR directives, considering multi-stage builds
        first_from_index = -1
        last_run_index = -1
        for i, line in enumerate(lines):
            line_upper = line.strip().upper()
            if line_upper.startswith("FROM"):
                if first_from_index == -1: # Capture index of the first FROM
                    first_from_index = i
            elif line_upper.startswith("RUN"):
                last_run_index = i
            
            if line_upper.startswith("USER"):
                user_set_explicitly = True
            if line_upper.startswith("WORKDIR"):
                workdir_set = True

        updated_any_rule = False

        # Rule 1: Add USER if not set to non-root or if 'USER root' is explicitly used.
        user_root_lines = [i for i, line in enumerate(new_lines) if line.strip().upper() == "USER ROOT"]
        
        if user_root_lines:
            logging.info("Found 'USER root' instruction(s), attempting to replace with non-root user.")
            temp_new_lines = []
            for i, line in enumerate(new_lines):
                if i in user_root_lines:
                    user_add_commands_to_insert = [
                        "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n",
                        "USER appuser\n"
                    ]
                    
                    from_line_for_stage = ""
                    for j in range(i, -1, -1):
                        if new_lines[j].strip().upper().startswith("FROM"):
                            from_line_for_stage = new_lines[j].lower()
                            break

                    if "node:" in from_line_for_stage:
                        user_add_commands_to_insert = ["USER node\n"]
                    elif "alpine" in from_line_for_stage:
                        user_add_commands_to_insert = [
                            "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n",
                            "USER appuser\n"
                        ]
                    elif "debian" in from_line_for_stage or "ubuntu" in from_line_for_stage:
                         user_add_commands_to_insert = [
                            "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n",
                            "USER appuser\n"
                        ]

                    temp_new_lines.extend(user_add_commands_to_insert)
                    logging.info(f"Replaced 'USER root' with: {' '.join([cmd.strip() for cmd in user_add_commands_to_insert])}")
                    updated_any_rule = True
                else:
                    temp_new_lines.append(line)
            new_lines = temp_new_lines
        elif not user_set_explicitly and first_from_index != -1:
            insert_index = last_run_index if last_run_index > first_from_index else first_from_index + 1
            
            user_add_commands_to_insert = [
                "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n",
                "USER appuser\n"
            ]
            from_line = next((l for l in lines if l.strip().upper().startswith("FROM")), "").lower()
            if "node:" in from_line:
                user_add_commands_to_insert = ["USER node\n"]
            elif "alpine" in from_line:
                user_add_commands_to_insert = [
                    "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n", 
                    "USER appuser\n"
                ]
            elif "debian" in from_line or "ubuntu" in from_line:
                 user_add_commands_to_insert = [
                    "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n", 
                    "USER appuser\n"
                ]

            new_lines[insert_index:insert_index] = user_add_commands_to_insert
            logging.info("Added non-root user to Dockerfile.")
            updated_any_rule = True
        else:
            logging.info("Dockerfile already has a non-root USER instruction or no suitable insertion point. Skipping user hardening.")
        
        # Rule 2: Add WORKDIR if not set (best practice)
        if not workdir_set:
            insert_point_found = False
            for i, line in enumerate(new_lines):
                if line.strip().upper().startswith("USER") and i + 1 < len(new_lines):
                    new_lines.insert(i + 1, "WORKDIR /app\n")
                    logging.info("Added WORKDIR /app to Dockerfile after USER.")
                    updated_any_rule = True
                    insert_point_found = True
                    break
                elif line.strip().upper().startswith("FROM") and not insert_point_found and i + 1 < len(new_lines):
                    stage_has_workdir = False
                    for j in range(i + 1, len(new_lines)):
                        if new_lines[j].strip().upper().startswith("FROM"):
                            break
                        if new_lines[j].strip().upper().startswith("WORKDIR"):
                            stage_has_workdir = True
                            break
                    if not stage_has_workdir:
                        new_lines.insert(i + 1, "WORKDIR /app\n")
                        logging.info("Added WORKDIR /app to Dockerfile after FROM.")
                        updated_any_rule = True
                        insert_point_found = True
                        break

            if not insert_point_found:
                last_from_idx = -1
                for i, line in enumerate(new_lines):
                    if line.strip().upper().startswith("FROM"):
                        last_from_idx = i
                
                if last_from_idx != -1:
                    new_lines.insert(last_from_idx + 1, "WORKDIR /app\n")
                    logging.info("Added WORKDIR /app to Dockerfile after last FROM.")
                    updated_any_rule = True
                else:
                    new_lines.insert(0, "WORKDIR /app\n")
                    logging.warning("No FROM instruction found. Added WORKDIR /app at start of Dockerfile.")
                    updated_any_rule = True
        else:
            logging.info("Dockerfile already has a WORKDIR instruction. Skipping WORKDIR hardening.")

        if updated_any_rule:
            return atomic_write_file(dockerfile_path, "".join(new_lines))
        else:
            logging.info("No significant Dockerfile hardening changes needed (USER and WORKDIR are present/handled).")
            return False

    except Exception as e:
        logging.error(f"Error hardening Dockerfile '{dockerfile_path}': {e}")
        return False

def modify_dockerfile_for_npm_legacy_peer_deps(dockerfile_path):
    """
    Modifies the Dockerfile to use 'npm install --legacy-peer-deps' if 'RUN npm install' is found.
    Returns True if modified, False otherwise.
    """
    logging.info(f"Attempting to modify Dockerfile {dockerfile_path} for npm --legacy-peer-deps.")
    if not os.path.exists(dockerfile_path):
        logging.warning(f"Dockerfile '{dockerfile_path}' not found for modification. Skipping.")
        return False

    try:
        with open(dockerfile_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = []
        modified = False
        for line in lines:
            if re.match(r'^\s*RUN\s+npm\s+install\s*$', line, re.IGNORECASE):
                new_line = line.replace("npm install", "npm install --legacy-peer-deps").strip() + "\n"
                new_lines.append(new_line)
                logging.info(f"Modified 'RUN npm install' to '{new_line.strip()}' in Dockerfile.")
                modified = True
            else:
                new_lines.append(line)
        
        if modified:
            return atomic_write_file(dockerfile_path, "".join(new_lines))
        else:
            logging.info(f"No 'RUN npm install' instruction found in {dockerfile_path} to modify.")
            return False
    except Exception as e:
        logging.error(f"Error modifying Dockerfile for npm --legacy-peer-deps in '{dockerfile_path}': {e}")
        return False

def build_docker_image(dockerfile_path, image_name, app_root_dir):
    """
    Builds a Docker image. Adds a retry with --legacy-peer-deps if initial build fails due to npm ERESOLVE.
    Returns True on success, False on failure.
    """
    cmd = ["docker", "build", "-f", os.path.basename(dockerfile_path), "-t", image_name, "."]
    
    logging.info(f"Attempting to build Docker image '{image_name}' from {dockerfile_path}")
    
    success, stderr_output = run_command(cmd, cwd=app_root_dir, check_result=False, capture_output=True, description="docker build")

    if not success:
        if "npm error code ERESOLVE" in stderr_output:
            logging.warning("Docker build failed due to npm ERESOLVE error. Attempting to apply --legacy-peer-deps fix.")
            
            original_dockerfile_content = None
            if os.path.exists(dockerfile_path):
                with open(dockerfile_path, 'r', encoding='utf-8') as f:
                    original_dockerfile_content = f.read()

            if modify_dockerfile_for_npm_legacy_peer_deps(dockerfile_path):
                logging.info("Dockerfile modified. Retrying docker build with --legacy-peer-deps.")
                success_retry, _ = run_command(cmd, cwd=app_root_dir, check_result=False, description="docker build with --legacy-peer-deps")
                if success_retry:
                    logging.warning("\n" + "="*80 + "\n")
                    logging.warning("!!! IMPORTANT: Docker image built successfully using '--legacy-peer-deps'.")
                    logging.warning("!!! This indicates an underlying npm dependency conflict (ERESOLVE).")
                    logging.warning("!!! This fix is a workaround. The development team should resolve this conflict in package.json.")
                    logging.warning("!!! Consider creating an issue/PR to address the root cause.\n")
                    logging.warning("="*80 + "\n")
                    return True
                else:
                    logging.error("Retried docker build with --legacy-peer-deps, but it still failed. Rolling back Dockerfile.")
                    if original_dockerfile_content:
                        atomic_write_file(dockerfile_path, original_dockerfile_content)
                        logging.info("Dockerfile rolled back to original state.")
                    return False
            else:
                logging.error("Failed to modify Dockerfile for --legacy-peer-deps. Build remains failed.")
                return False
        else:
            logging.error(f"Docker build failed for reasons other than npm ERESOLVE. See logs above.")
            return False
    else:
        logging.info(f"Successfully built Docker image: {image_name}")
        return True

def parse_vulnerability_report(report_path):
    """
    Parses a vulnerability report (e.g., Trivy JSON) and extracts
    actionable remediation steps. This is a simplified mock.
    In a real scenario, you would parse actual CVEs and their fix versions.
    """
    logging.info(f"Parsing vulnerability report from {report_path}.")
    remediations = []
    if not os.path.exists(report_path):
        logging.warning(f"Trivy report '{report_path}' not found. No direct dependency fixes will be attempted from report.")
        return remediations
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        for result in report_data.get('Results', []):
            target = result.get('Target', '')
            for vuln in result.get('Vulnerabilities', []):
                # Only consider critical/high and if a fix version is available
                if vuln.get('Severity') in ['CRITICAL', 'HIGH'] and vuln.get('FixedVersion'):
                    pkg_name = vuln.get('PkgName')
                    fixed_version = vuln.get('FixedVersion')
                    vulnerability_id = vuln.get('VulnerabilityID')
                    
                    # Heuristic to determine package manager based on target/path
                    # This needs to be robust, perhaps using known file patterns
                    pkg_type = "unknown"
                    if "npm" in target.lower() or "node_modules" in target.lower():
                        pkg_type = "npm"
                    elif "pip" in target.lower() or "python" in target.lower() or "requirements.txt" in target.lower():
                        pkg_type = "pip"
                    elif "gem" in target.lower() or "ruby" in target.lower() or "gemfile" in target.lower():
                        pkg_type = "gem"
                    elif "go.mod" in target.lower() or "go" in target.lower():
                        pkg_type = "go"

                    if pkg_type != "unknown":
                        remediations.append({
                            "type": pkg_type,
                            "package": pkg_name,
                            "fixed_version": fixed_version,
                            "vulnerability_id": vulnerability_id,
                            "app_path": os.environ.get('APP_ROOT_DIR', '.') # Assume app_root_dir covers this target
                        })
        logging.info(f"Found {len(remediations)} actionable vulnerabilities from report.")
        return remediations
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON report '{report_path}': {e}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred while parsing report '{report_path}': {e}")
        return []

def main():
    # Retrieve environment variables passed from GitHub Actions workflow
    workspace_root = os.getcwd() # GitHub Actions runner sets CWD to repo root
    app_root_dir = os.environ.get('APP_ROOT_DIR')
    dockerfile_path = os.environ.get('DOCKERFILE_PATH')
    base_image_name = os.environ.get('IMAGE_NAME') # Base image name without tag
    trivy_report_path = os.environ.get('TRIVY_REPORT_PATH', 'trivy-report.json')

    if not app_root_dir or not dockerfile_path or not base_image_name:
        logging.error("Missing required environment variables (APP_ROOT_DIR, DOCKERFILE_PATH, IMAGE_NAME). Exiting.")
        sys.exit(1)

    # Ensure paths are absolute or correctly relative to the current working directory (repo root)
    app_root_dir = os.path.join(workspace_root, app_root_dir)
    dockerfile_path = os.path.join(workspace_root, dockerfile_path)
    # The Trivy report is downloaded to the current working directory, so it's fine.

    logging.info(f"Starting automated vulnerability remediation pipeline for {app_root_dir}")
    logging.info(f"Dockerfile Path: {dockerfile_path}")
    logging.info(f"Base Image Name: {base_image_name}")

    changes_made = False
    remediation_status = "no_changes" # Can be: no_changes, applied_fixes, build_failed, scan_failed, vulns_remain, success

    # Step 1: Apply general Dockerfile hardening
    logging.info("Attempting to apply general Dockerfile hardening rules.")
    if harden_dockerfile(dockerfile_path):
        changes_made = True
        logging.info("Dockerfile hardening changes applied.")
    else:
        logging.info("No Dockerfile hardening changes were applied or needed.")

    # Step 2: Parse initial Trivy report and apply specific dependency fixes
    logging.info(f"Parsing initial Trivy report: {trivy_report_path}")
    remediations = parse_vulnerability_report(trivy_report_path)
    
    for rem in remediations:
        logging.info(f"Attempting to fix {rem['type']} package: {rem['package']} to version {rem['fixed_version']} for {rem['vulnerability_id']}")
        fix_success = False
        if rem["type"] == "npm":
            fix_success = fix_npm_dependency(rem["package"], rem["fixed_version"], app_root_dir)
        elif rem["type"] == "pip":
            fix_success = fix_pip_dependency(rem["package"], rem["fixed_version"], app_root_dir)
        elif rem["type"] == "gem":
            fix_success = fix_gem_dependency(rem["package"], rem["fixed_version"], app_root_dir)
        elif rem["type"] == "go":
            fix_success = fix_go_dependency(rem["package"], rem["fixed_version"], app_root_dir)
        
        if fix_success:
            changes_made = True
            logging.info(f"Successfully applied fix for {rem['package']}@{rem['fixed_version']}.")
        else:
            logging.warning(f"Failed to apply fix for {rem['package']}@{rem['fixed_version']}. Manual intervention may be needed for {rem['vulnerability_id']}.")

    # Use Git to detect if any files were modified by the remediation steps
    try:
        logging.info("Checking for any file changes from remediation steps using git status.")
        run_command(["git", "add", "."], cwd=workspace_root, description="git add all changes", check_result=True)
        success, git_output = run_command(["git", "status", "--porcelain"], cwd=workspace_root, capture_output=True, check_result=True, description="git status --porcelain")
        
        if success and git_output:
            logging.info("Changes detected in the repository after remediation steps.")
            changes_made = True
        else:
            logging.info("No new changes detected in the repository after remediation steps.")
            # If no changes, ensure 'changes_made' flag is respected.
            # If it was True due to Dockerfile hardening, keep it True.
            # If no hardening and no dependency fixes, it should remain False.
            if not changes_made: # Only set to False if no changes were initially detected (e.g. from hardening)
                changes_made = False

    except Exception as e:
        logging.error(f"An error occurred during git status check: {e}. Assuming changes to proceed with build.")
        changes_made = True 
        remediation_status = "git_check_failed"

    remediated_image_tag_file = "remediated_image_tag.txt"
    remediated_scan_report_file = "trivy-remediated-scan-report.json"
    remediated_image_name_with_tag = ""

    if changes_made:
        logging.info("Changes were made. Proceeding with Docker image rebuild and re-scan.")
        timestamp = int(time.time())
        remediated_image_name_with_tag = f"{base_image_name}:remediated-{timestamp}"
        
        # Step 3: Rebuild the image with patched components
        logging.info(f"Attempting to rebuild Docker image: {remediated_image_name_with_tag}")
        if build_docker_image(dockerfile_path, remediated_image_name_with_tag, app_root_dir):
            logging.info(f"Docker image '{remediated_image_name_with_tag}' built successfully.")
            
            # Write the new image tag to a file for the workflow to use
            try:
                with open(remediated_image_tag_file, 'w') as f:
                    f.write(remediated_image_name_with_tag)
                logging.info(f"Wrote remediated image tag '{remediated_image_name_with_tag}' to {remediated_image_tag_file}")
            except Exception as e:
                logging.error(f"Failed to write remediated image tag to file: {e}")
                remediation_status = "tag_file_write_failed"
                sys.exit(1) # Fail if we can't communicate the new tag

            # Step 4: Re-scan the newly built image to confirm zero known vulnerabilities remain
            logging.info(f"Re-scanning remediated image '{remediated_image_name_with_tag}' with Trivy.")
            scan_cmd = ["trivy", "image", "--format", "json", "--output", remediated_scan_report_file, remediated_image_name_with_tag]
            
            success_scan, scan_output = run_command(scan_cmd, cwd=workspace_root, check_result=False, capture_output=True, description="Trivy re-scan")
            
            if success_scan:
                logging.info(f"Trivy re-scan completed for {remediated_image_name_with_tag}. Analyzing report...")
                # Analyze the remediated scan report for remaining critical/high vulnerabilities
                try:
                    with open(remediated_scan_report_file, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    
                    remaining_vulns = []
                    for result in report_data.get('Results', []):
                        for vuln in result.get('Vulnerabilities', []):
                            if vuln.get('Severity') in ['CRITICAL', 'HIGH']:
                                remaining_vulns.append(vuln)

                    if remaining_vulns:
                        logging.error(f"Remediated image '{remediated_image_name_with_tag}' still has Critical/High vulnerabilities. Remediation failed.")
                        for vuln in remaining_vulns:
                            logging.error(f"  - {vuln.get('VulnerabilityID')}: {vuln.get('PkgName')} ({vuln.get('Severity')}) - Fixed In: {vuln.get('FixedVersion', 'N/A')}")
                        remediation_status = "vulns_remain"
                        sys.exit(1) # Indicate failure for the workflow
                    else:
                        logging.info(f"Remediated image '{remediated_image_name_with_tag}' is clean of Critical/High vulnerabilities. Success!")
                        remediation_status = "success"
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to parse remediated scan report '{remediated_scan_report_file}': {e}")
                    remediation_status = "scan_report_parse_failed"
                    sys.exit(1)
                except Exception as e:
                    logging.error(f"An unexpected error occurred during re-scan report analysis: {e}")
                    remediation_status = "scan_report_analysis_error"
                    sys.exit(1)
            else:
                logging.error(f"Trivy re-scan failed for {remediated_image_name_with_tag}. Please investigate.")
                remediation_status = "scan_failed"
                sys.exit(1)
        else:
            logging.error("Failed to rebuild Docker image after remediation attempts. Review logs for details.")
            remediation_status = "build_failed"
            sys.exit(1)
    else:
        logging.info("No remediation changes were applied or detected. Exiting without further action.")
        remediation_status = "no_changes"
    
    # At the very end, if the script successfully completed remediation steps
    # and a new image was built, it should push it.
    # We are assuming the 'docker/build-push-action@v5' handles the push,
    # or the build_docker_image function in the script needs to be modified
    # to perform `docker push`. Given the workflow already has a build-push-action,
    # the script should just *build* locally if needed, and the workflow itself
    # should re-trigger a build/push for the remediated code.
    # For now, `build_docker_image` in the script only builds, not pushes.
    # The GitHub Action flow will handle the push via `git auto-commit`.
    
    # If we reached here, it means the script ran to completion,
    # even if remediation_status is "no_changes".
    # The workflow will use the `remediated_image_tag.txt` and `trivy-remediated-scan-report.json`
    # for subsequent steps.
    logging.info(f"Remediation pipeline finished with status: {remediation_status}")
    
    # Exit with a non-zero code if remediation ultimately failed,
    # allowing the GitHub Actions job to fail.
    if remediation_status in ["build_failed", "scan_failed", "vulns_remain", "scan_report_parse_failed", "scan_report_analysis_error", "tag_file_write_failed", "git_check_failed"]:
        sys.exit(1) # Indicate a failure to the workflow
    else:
        sys.exit(0) # Indicate success

if __name__ == "__main__":
    # The main function is now explicitly called
    # when the script is executed.
    main()
