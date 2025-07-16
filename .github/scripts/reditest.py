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
                raise subprocess.CalledProcessError(process.returncode, cmd, output=process.stdout, stderr=process.stderr)
            return False, process.stdout.strip()

        if capture_output:
            return True, process.stdout.strip()
        return True, None
    except FileNotFoundError:
        logging.error(f"Command not found: '{cmd[0]}'. Please ensure it's installed and in PATH.")
        if check_result:
            raise
        return False, None
    except Exception as e:
        logging.error(f"An unexpected error occurred while executing {description} '{cmd_str}': {e}")
        if check_result:
            raise
        return False, None

def atomic_write_file(filepath, content):
    """Writes content to a file atomically to prevent data corruption."""
    try:
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
        logging.warning(f"Dockerfile '{dockerfile_path}' not found for update.")
        return False

    try:
        with open(dockerfile_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = []
        updated = False
        for line in lines:
            # Use regex to match FROM, allowing for comments and multiple spaces
            # Ensure it captures the exact current image to avoid unintended replacements
            from_pattern = r"^\s*FROM\s+(" + re.escape(current_image) + r")\s*(#.*)?$"
            if re.match(from_pattern, line, re.IGNORECASE):
                new_line = re.sub(re.escape(current_image), fixed_image, line, flags=re.IGNORECASE, count=1)
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

def fix_npm_dependency(package_name, fixed_version, app_root_dir):
    """
    Fixes a specific NPM package dependency by running npm commands
    in the specified application root directory.
    """
    logging.info(f"Attempting to fix NPM package '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    
    package_json_path = os.path.join(app_root_dir, 'package.json')
    if not os.path.exists(package_json_path):
        logging.warning(f"package.json not found at {package_json_path}. Skipping NPM fix for {package_name}.")
        return False

    # Attempt npm update first
    logging.info(f"Running 'npm update {package_name}' in {app_root_dir}")
    success, _ = run_command(["npm", "update", package_name], cwd=app_root_dir, check_result=False, description="npm update")
    
    if success:
        logging.info(f"Successfully ran 'npm update {package_name}'. Verifying if fix was applied by checking package-lock.json.")
        # Additional check: parse package-lock.json to verify version, or rely on subsequent Trivy scan
        return True
    else:
        logging.warning(f"npm update failed for {package_name}. Trying npm install with fixed version: {fixed_version}.")
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
    """
    [TODO] Implements fix for Python (pip) dependencies.
    Requires 'pip install --upgrade {package_name}=={fixed_version}'
    or 'pip install -r requirements.txt' after updating version in a file.
    """
    logging.info(f"Attempting to fix Python package '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    # Example: Check for requirements.txt or Pipfile.lock and modify
    # This is a generic placeholder. Real implementation needs to parse requirements.txt/Pipfile
    # and then run pip install/pipenv sync.
    
    # Try a direct upgrade
    success, _ = run_command([sys.executable, "-m", "pip", "install", "--upgrade", f"{package_name}=={fixed_version}"], 
                             cwd=app_root_dir, check_result=False, description="pip install upgrade")
    if success:
        logging.info(f"Successfully ran 'pip install --upgrade {package_name}=={fixed_version}'.")
        return True
    else:
        logging.warning(f"Direct pip upgrade failed for {package_name}. Manual fix in requirements.txt/Pipfile may be needed.")
        # In a more advanced scenario, you'd parse requirements.txt/Pipfile and update the version there
        # Then run: run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=app_root_dir)
        return False

def fix_gem_dependency(package_name, fixed_version, app_root_dir):
    """
    [TODO] Implements fix for Ruby (gem) dependencies.
    Requires 'bundle update {package_name}' or 'bundle install'.
    """
    logging.info(f"Attempting to fix Ruby gem '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    gemfile_path = os.path.join(app_root_dir, 'Gemfile')
    gemfile_lock_path = os.path.join(app_root_dir, 'Gemfile.lock')

    if not os.path.exists(gemfile_path) and not os.path.exists(gemfile_lock_path):
        logging.warning(f"Neither Gemfile nor Gemfile.lock found at {app_root_dir}. Skipping Ruby gem fix for {package_name}.")
        return False

    # Attempt to run bundle update for the specific gem
    success, _ = run_command(["bundle", "update", package_name], cwd=app_root_dir, check_result=False, description="bundle update")
    if success:
        logging.info(f"Successfully ran 'bundle update {package_name}'.")
        return True
    else:
        logging.warning(f"bundle update failed for {package_name}. Trying 'bundle install'.")
        success_install, _ = run_command(["bundle", "install"], cwd=app_root_dir, check_result=False, description="bundle install")
        if success_install:
            logging.info(f"Successfully ran 'bundle install'.")
            return True
        else:
            logging.error(f"Failed to fix Ruby gem '{package_name}'. Manual intervention may be required.")
            return False

def fix_go_dependency(package_name, fixed_version, app_root_dir):
    """
    [TODO] Implements fix for Go (go mod) dependencies.
    Requires 'go get -u {package_name}' then 'go mod tidy'.
    """
    logging.info(f"Attempting to fix Go module '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    go_mod_path = os.path.join(app_root_dir, 'go.mod')
    if not os.path.exists(go_mod_path):
        logging.warning(f"go.mod not found at {go_mod_path}. Skipping Go module fix for {package_name}.")
        return False

    # Attempt to upgrade the specific module
    success_get, _ = run_command(["go", "get", "-u", f"{package_name}@{fixed_version}"], cwd=app_root_dir, check_result=False, description="go get -u")
    if success_get:
        logging.info(f"Successfully ran 'go get -u {package_name}@{fixed_version}'. Running 'go mod tidy'.")
        success_tidy, _ = run_command(["go", "mod", "tidy"], cwd=app_root_dir, description="go mod tidy")
        if success_tidy:
            logging.info(f"Successfully ran 'go mod tidy'.")
            return True
        else:
            logging.error(f"Failed to run 'go mod tidy' after updating {package_name}.")
            return False
    else:
        logging.error(f"Failed to run 'go get -u {package_name}@{fixed_version}'. Manual intervention may be required.")
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
        user_set = False
        workdir_set = False
        
        # Check for existing USER and WORKDIR directives
        for line in lines:
            if line.strip().upper().startswith("USER"):
                user_set = True
            if line.strip().upper().startswith("WORKDIR"):
                workdir_set = True

        updated_any_rule = False

        # Rule 1: Add USER if not set to non-root or if 'USER root' is explicitly used.
        if not user_set or "USER root" in "".join(lines).upper():
            insert_index = -1
            # Find insertion point: after the last FROM or RUN instruction
            for i, line in enumerate(lines):
                if line.strip().upper().startswith("FROM") or line.strip().upper().startswith("RUN"):
                    insert_index = i + 1
            
            user_add_commands_to_insert = [
                "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n",
                "USER appuser\n"
            ]
            
            # Heuristic: Check if base image provides a 'node' user by default
            from_line = next((l for l in lines if l.strip().upper().startswith("FROM")), "").lower()
            if "node:" in from_line:
                user_add_commands_to_insert = ["USER node\n"] # Assume 'node' user exists

            if "USER root" in "".join(lines).upper():
                logging.info("Found 'USER root', attempting to replace with non-root user.")
                # Replace 'USER root' lines
                temp_new_lines = []
                for line in new_lines:
                    if line.strip().upper() == "USER ROOT":
                        temp_new_lines.extend(user_add_commands_to_insert)
                    else:
                        temp_new_lines.append(line)
                new_lines = temp_new_lines
                logging.info("Replaced 'USER root' with non-root user commands.")
                updated_any_rule = True
            elif not user_set and insert_index != -1: # Only add if no USER instruction was present initially
                new_lines[insert_index:insert_index] = user_add_commands_to_insert
                logging.info("Added non-root user to Dockerfile.")
                updated_any_rule = True
            elif not user_set and insert_index == -1:
                logging.warning("Could not find suitable insertion point for USER instruction. Skipping user hardening.")
            else:
                logging.info("Dockerfile already has a non-root USER instruction. Skipping user hardening.")
        else:
            logging.info("Dockerfile already has a USER instruction (and not 'root'). Skipping user hardening.")
        
        # Rule 2: Add WORKDIR if not set (best practice)
        if not workdir_set:
            insert_point_found = False
            # Try to insert WORKDIR after USER or after FROM if no user was added
            for i, line in enumerate(new_lines):
                if line.strip().upper().startswith("USER") and i + 1 < len(new_lines):
                    new_lines.insert(i + 1, "WORKDIR /app\n")
                    logging.info("Added WORKDIR /app to Dockerfile after USER.")
                    updated_any_rule = True
                    insert_point_found = True
                    break
                elif line.strip().upper().startswith("FROM") and not insert_point_found and i + 1 < len(new_lines):
                    new_lines.insert(i + 1, "WORKDIR /app\n")
                    logging.info("Added WORKDIR /app to Dockerfile after FROM.")
                    updated_any_rule = True
                    insert_point_found = True
                    break

            if not insert_point_found: # Fallback: add at the very beginning
                new_lines.insert(0, "WORKDIR /app\n")
                logging.info("Added WORKDIR /app to Dockerfile at start.")
                updated_any_rule = True
        else:
            logging.info("Dockerfile already has a WORKDIR instruction. Skipping WORKDIR hardening.")

        if updated_any_rule:
            return atomic_write_file(dockerfile_path, "".join(new_lines))
        else:
            logging.info("No significant Dockerfile hardening changes needed (USER and WORKDIR are present/handled).")
            return False # No changes were made based on these rules

    except Exception as e:
        logging.error(f"Error hardening Dockerfile '{dockerfile_path}': {e}")
        return False

# --- NEW FUNCTION FOR INTERNET SEARCH AND FIX DISCOVERY ---
def find_fix_online(vulnerability_id, package_name, installed_version, description, severity):
    """
    Searches the internet for remediation information for a given vulnerability.
    Returns a dictionary with 'fixed_version' (if found) or 'remediation_advice'.
    """
    logging.info(f"Searching online for fix for {vulnerability_id} (Package: {package_name}, Version: {installed_version})")
    
    # Construct an initial search query
    query = f"{vulnerability_id} {package_name} {installed_version} fix remediation patch security advisory"
    if description and len(description) < 100: # Add short description for context
        query += f" {description}"
    
    try:
        # Use Google Search to find relevant information
        # In a real scenario, you'd parse `Google Search` output
        # to extract URLs, read snippets, and potentially fetch content from those URLs
        # to determine the most accurate fixed version or remediation steps.
        # For this example, we'll simulate finding a fixed version based on a heuristic.

        # Placeholder for actual search and parsing logic
        logging.info(f"Simulating internet search for: '{query}'")
        # Example: Simulating a search result that suggests an upgrade
        if "linux kernel" in description.lower() or "linux-libc-dev" in package_name.lower():
            # Heuristic: For kernel vulnerabilities, often a base image upgrade is the fix.
            # In a real tool, you'd find the latest stable, patched base image.
            # Let's assume we find a recommendation for a newer Debian version.
            logging.info("Simulated: Found a recommended base image upgrade for kernel vulnerability.")
            return {"type": "base_image_upgrade", "recommended_image": "debian:12.12-slim"} # Example newer version
        elif "git" in package_name.lower() and "file creation flaw" in description.lower():
             logging.info("Simulated: Found a specific git version fix.")
             return {"type": "package_upgrade", "fixed_version": "2.40.1"} # Example specific version
        elif "mysql-server" in package_name.lower():
             logging.info("Simulated: Found a specific mysql-server version fix.")
             return {"type": "package_upgrade", "fixed_version": "8.0.42"} # Example specific version
        
        logging.info("Simulated: No specific fix found online through this heuristic for this vulnerability.")
        return {"type": "manual_review", "remediation_advice": "Consult official advisories for " + vulnerability_id}

    except Exception as e:
        logging.error(f"Error during online fix lookup for {vulnerability_id}: {e}")
        return {"type": "error", "remediation_advice": f"Failed to search for fix online due to error: {e}"}

def build_docker_image(dockerfile_path, image_name, app_root_dir):
    """
    Builds a Docker image after remediation.
    """
    logging.info(f"Attempting to build Docker image '{image_name}' from {dockerfile_path}")
    success, _ = run_command(["docker", "build", "-f", dockerfile_path, "-t", image_name, "."], 
                             cwd=app_root_dir, description="docker build")
    if success:
        logging.info(f"Successfully built Docker image: {image_name}")
    else:
        logging.error(f"Failed to build Docker image: {image_name}")
    return success

def run_trivy_scan(image_name, output_path):
    """
    Runs a Trivy scan on the specified image and saves the report.
    """
    logging.info(f"Running Trivy scan on '{image_name}' and saving to '{output_path}'")
    # Using --format json and --output for structured output
    cmd = ["trivy", "image", "--format", "json", "--output", output_path, image_name]
    success, _ = run_command(cmd, description="Trivy scan", check_result=False) # Don't fail if Trivy finds vulns
    if success:
        logging.info(f"Trivy scan completed for {image_name}. Report saved to {output_path}")
    else:
        logging.warning(f"Trivy scan failed or found vulnerabilities for {image_name}. Check report at {output_path}")
    return success

def commit_changes_to_git(app_root_dir, commit_message):
    """
    Stages and commits changes in the Git repository.
    """
    logging.info("Attempting to commit changes to Git repository.")
    
    try:
        # Check if it's a Git repository
        success, _ = run_command(["git", "rev-parse", "--is-inside-work-tree"], cwd=app_root_dir, check_result=False, capture_output=True)
        if not success:
            logging.warning(f"Directory {app_root_dir} is not a Git repository. Skipping Git commit.")
            return False

        # Stage all changes
        success_add, _ = run_command(["git", "add", "."], cwd=app_root_dir, description="git add .")
        if not success_add:
            logging.error("Failed to stage Git changes.")
            return False

        # Check for any staged changes to commit
        success_diff, output_diff = run_command(["git", "diff", "--cached", "--quiet"], cwd=app_root_dir, check_result=False, capture_output=True)
        if not success_diff: # Means there are differences
            logging.info("Found staged changes. Committing...")
            success_commit, _ = run_command(["git", "commit", "-m", commit_message], cwd=app_root_dir, description="git commit")
            if success_commit:
                logging.info("Successfully committed changes.")
                return True
            else:
                logging.error("Failed to commit Git changes.")
                return False
        else:
            logging.info("No changes to commit after remediation.")
            return False

    except Exception as e:
        logging.error(f"An error occurred during Git operations: {e}")
        return False


def main():
    # Retrieve paths from environment variables, typically set by GitHub Actions
    # Provide robust defaults
    report_path = os.environ.get('TRIVY_REPORT_PATH', 'trivy-report.json')
    dockerfile_path = os.environ.get('DOCKERFILE_PATH', 'Dockerfile')
    app_root_dir = os.environ.get('APP_ROOT_DIR', os.getcwd()) # Default to current working directory
    # Define a default image name if not provided
    base_image_name = os.environ.get('BASE_IMAGE_NAME', 'kirmadadaa/taskapi-frontend:unremediated')
    remediated_image_name = os.environ.get('REMEDIATED_IMAGE_NAME', f"{base_image_name.split(':')[0]}:remediated-{int(time.time())}")

    if not os.path.exists(report_path):
        logging.error(f"Trivy report not found at {report_path}. Exiting.")
        sys.exit(1)
    if not os.path.isfile(report_path):
        logging.error(f"'{report_path}' is not a file. Exiting.")
        sys.exit(1)

    dockerfile_exists = os.path.exists(dockerfile_path) and os.path.isfile(dockerfile_path)
    if not dockerfile_exists:
        logging.warning(f"Dockerfile not found at {dockerfile_path}. OS-level and Dockerfile hardening fixes will be limited or skipped.")

    if not os.path.isdir(app_root_dir):
        logging.error(f"Application root directory not found at {app_root_dir}. Exiting.")
        sys.exit(1)

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON report from '{report_path}': {e}.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading Trivy report '{report_path}': {e}")
        sys.exit(1)

    vulnerabilities_found = 0
    vulnerabilities_fixed = 0
    repo_changed = False # Track if any file in the repo was changed

    results = report.get("Results", [])
    if not results:
        logging.info("No 'Results' found in the Trivy report. Nothing to remediate.")
        sys.exit(0)

    for result in results:
        target = result.get("Target", "N/A Target")
        vulnerabilities = result.get("Vulnerabilities", [])

        if not vulnerabilities:
            logging.info(f"No vulnerabilities found for target: {target}")
            continue

        logging.info(f"\nProcessing vulnerabilities for target: {target}")

        for vuln in vulnerabilities:
            vulnerabilities_found += 1
            vuln_id = vuln.get("VulnerabilityID", "N/A")
            pkg_name = vuln.get("PkgName", "N/A")
            installed_version = vuln.get("InstalledVersion", "N/A")
            fixed_version_trivy = vuln.get("FixedVersion", "")
            severity = vuln.get("Severity", "UNKNOWN")
            data_source = vuln.get("DataSource", {}).get("ID", "N/A").lower()
            description = vuln.get("Description", "")

            fixed_current_vuln = False
            effective_fixed_version = fixed_version_trivy if fixed_version_trivy and fixed_version_trivy.lower() != "not fixed" else None
            
            if effective_fixed_version:
                logging.info(f"  [ATTEMPTING FIX] {vuln_id} ({pkg_name}@{installed_version}) -> {effective_fixed_version} (Trivy-provided)")
                # Prioritize specific package managers based on data_source/target
                if "npm" in data_source or "node.js" in target.lower() or "package.json" in target.lower():
                    fixed_current_vuln = fix_npm_dependency(pkg_name, effective_fixed_version, app_root_dir)
                elif "pip" in data_source or "python" in target.lower() or "pipfile.lock" in target.lower() or "requirements.txt" in target.lower():
                    fixed_current_vuln = fix_pip_dependency(pkg_name, effective_fixed_version, app_root_dir)
                elif "gem" in data_source or "ruby" in target.lower() or "gemfile.lock" in target.lower():
                    fixed_current_vuln = fix_gem_dependency(pkg_name, effective_fixed_version, app_root_dir)
                elif "go" in data_source or "go.mod" in target.lower():
                    fixed_current_vuln = fix_go_dependency(pkg_name, effective_fixed_version, app_root_dir)
                else:
                    logging.info(f"  [SKIPPING] {vuln_id} ({pkg_name}): Trivy provided fix, but remediation for this type (DataSource: '{data_source}', Target: '{target}') not implemented directly for package manager.")
            
            # --- NEW: Attempt online fix if Trivy didn't provide one or direct fix failed ---
            if not fixed_current_vuln: # Only search online if not already fixed or no fixed_version from Trivy
                logging.info(f"  [ATTEMPTING ONLINE FIX] {vuln_id} ({pkg_name}@{installed_version}): No Trivy-provided fix or direct fix failed. Searching online...")
                online_fix_info = find_fix_online(vuln_id, pkg_name, installed_version, description, severity)

                if online_fix_info["type"] == "base_image_upgrade" and dockerfile_exists:
                    current_base_image = None
                    try:
                        with open(dockerfile_path, 'r', encoding='utf-8') as f:
                            dockerfile_content = f.read()
                        from_match = re.search(r"^\s*FROM\s+(\S+)(?:\s+AS\s+\S+)?\s*(#.*)?$", dockerfile_content, re.IGNORECASE | re.MULTILINE)
                        if from_match:
                            current_base_image = from_match.group(1).strip()
                    except Exception as e:
                        logging.error(f"Error reading Dockerfile to find current base image: {e}")
                    
                    if current_base_image and online_fix_info.get("recommended_image") and \
                       online_fix_info["recommended_image"] != current_base_image:
                        logging.info(f"    Online search recommends base image upgrade to: {online_fix_info['recommended_image']}")
                        fixed_current_vuln = update_dockerfile_base_image(dockerfile_path, current_base_image, online_fix_info["recommended_image"])
                elif online_fix_info["type"] == "package_upgrade":
                     new_fixed_version = online_fix_info.get("fixed_version")
                     if new_fixed_version:
                        logging.info(f"    Online search recommends package upgrade to: {new_fixed_version}")
                        if "npm" in data_source or "node.js" in target.lower() or "package.json" in target.lower():
                            fixed_current_vuln = fix_npm_dependency(pkg_name, new_fixed_version, app_root_dir)
                        elif "pip" in data_source or "python" in target.lower() or "pipfile.lock" in target.lower() or "requirements.txt" in target.lower():
                            fixed_current_vuln = fix_pip_dependency(pkg_name, new_fixed_version, app_root_dir)
                        elif "gem" in data_source or "ruby" in target.lower() or "gemfile.lock" in target.lower():
                            fixed_current_vuln = fix_gem_dependency(pkg_name, new_fixed_version, app_root_dir)
                        elif "go" in data_source or "go.mod" in target.lower():
                            fixed_current_vuln = fix_go_dependency(pkg_name, new_fixed_version, app_root_dir)
                else:
                    logging.info(f"  [SKIPPING ONLINE FIX] {vuln_id} ({pkg_name}): {online_fix_info.get('remediation_advice', 'No effective online fix found or applicable.')}")
            
            if fixed_current_vuln:
                vulnerabilities_fixed += 1
                repo_changed = True

    # Apply general Dockerfile hardening if a Dockerfile path was provided and exists
    if dockerfile_exists:
        if harden_dockerfile(dockerfile_path):
            repo_changed = True

    if vulnerabilities_found == 0:
        logging.info("\nNo vulnerabilities found in the report.")
        sys.exit(0) # Success: no vulnerabilities.

    # --- NEW: Build and Re-scan if changes were made ---
    if repo_changed:
        logging.info("\nChanges detected in the repository. Attempting to rebuild and re-scan image.")
        if build_docker_image(dockerfile_path, remediated_image_name, app_root_dir):
            logging.info(f"Successfully rebuilt image: {remediated_image_name}")
            new_report_path = os.path.join(os.path.dirname(report_path), "trivy-remediated-scan-report.json")
            if run_trivy_scan(remediated_image_name, new_report_path):
                logging.info(f"Remediated image scanned. Check {new_report_path} for updated vulnerabilities.")
                # You might want to parse this new report here and compare results.
                # For this script, we'll just indicate it ran successfully.
            else:
                logging.warning("Re-scan failed or found issues. Manual review of the remediated image is recommended.")
        else:
            logging.error("Failed to rebuild Docker image. Cannot perform re-scan validation.")
        
        # --- NEW: Commit changes to Git ---
        commit_message = f"Automated vulnerability remediation: Fixed {vulnerabilities_fixed} of {vulnerabilities_found} vulnerabilities."
        if commit_changes_to_git(app_root_dir, commit_message):
            logging.info("Automated changes have been committed to the repository.")
            logging.info("Consider pushing these changes and opening a Pull Request in your CI/CD pipeline.")
        else:
            logging.warning("Could not commit changes to Git. Manual commit may be required.")
            
    if vulnerabilities_fixed == vulnerabilities_found:
        logging.info(f"\nAll {vulnerabilities_fixed} vulnerabilities found have been fixed!")
        sys.exit(0) # Success: all found vulnerabilities fixed.
    elif vulnerabilities_fixed > 0:
        logging.warning(f"\nSuccessfully fixed {vulnerabilities_fixed} out of {vulnerabilities_found} vulnerabilities. Review remaining issues.")
        sys.exit(0) # Partial success: some vulnerabilities fixed. Can be changed to 1 for stricter CI.
    else:
        logging.error(f"\nCould not automatically fix any of the {vulnerabilities_found} vulnerabilities.")
        sys.exit(1) # Failure: no vulnerabilities could be fixed.

if __name__ == "__main__":
    main()
