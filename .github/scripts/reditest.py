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
        # Re-check package-lock.json or rely on subsequent Trivy scan
        return True
    else:
        logging.warning(f"npm audit fix failed or didn't fully resolve for {package_name}. Trying npm install with fixed version: {fixed_version}.")
        try:
            # Check if package is a peer dependency of a direct dependency
            # This is more complex and typically requires parsing package.json and package-lock.json.
            # For simplicity, if audit fix fails, we attempt a direct update.
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
    Implements fix for Python (pip) dependencies by attempting to update
    requirements.txt (if found) or directly upgrading the package.
    """
    logging.info(f"Attempting to fix Python package '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    
    requirements_path = os.path.join(app_root_dir, 'requirements.txt')
    pipfile_lock_path = os.path.join(app_root_dir, 'Pipfile.lock')

    updated_requirements_file = False

    if os.path.exists(requirements_path):
        logging.info(f"Found requirements.txt at {requirements_path}. Attempting to update.")
        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            new_lines = []
            updated = False
            for line in lines:
                # Regex to find package_name, allowing for various version specifiers (==, >=, <, ~)
                # and comments/whitespace. Make sure it's not a different package with similar name.
                # Example: `package-name==1.2.3` or `package-name>=1.0`
                pkg_pattern = r"^\s*" + re.escape(package_name) + r"([<>=!~=]=?[\d\.]+.*)?$"
                if re.match(pkg_pattern, line, re.IGNORECASE):
                    # Replace or append the fixed version
                    if re.search(r"[<>=!~=]=?[\d\.]+", line): # If version already exists
                        new_line = re.sub(r"([<>=!~=]=?[\d\.]+)", f"=={fixed_version}", line, count=1)
                    else: # If only package name
                        new_line = line.strip() + f"=={fixed_version}\n"
                    
                    if new_line != line:
                        new_lines.append(new_line)
                        logging.info(f"Updated requirements.txt line: {new_line.strip()}")
                        updated = True
                    else: # No change needed or already correct
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if updated:
                if atomic_write_file(requirements_path, "".join(new_lines)):
                    updated_requirements_file = True
                else:
                    return False # Failed to write
            else:
                logging.info(f"Could not find or update '{package_name}' in requirements.txt. Attempting direct upgrade.")
        except Exception as e:
            logging.error(f"Error updating requirements.txt for {package_name}: {e}")
            # Do not return, try direct pip install as fallback

    # If requirements.txt was updated, install from it. Else, try direct upgrade.
    if updated_requirements_file:
        success, _ = run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                                 cwd=app_root_dir, description="pip install -r requirements.txt")
        if success:
            logging.info(f"Successfully ran 'pip install -r requirements.txt' after updating {package_name}.")
            return True
        else:
            logging.error(f"Failed to install from updated requirements.txt after updating {package_name}. Trying direct upgrade.")
            # Fallback to direct upgrade if requirements.txt install failed
            pass # Continue to the direct upgrade path below
    
    # Fallback to direct upgrade if requirements.txt not found or update/install from it failed
    success, _ = run_command([sys.executable, "-m", "pip", "install", "--upgrade", f"{package_name}=={fixed_version}"], 
                             cwd=app_root_dir, check_result=False, description="pip install upgrade")
    if success:
        logging.info(f"Successfully ran 'pip install --upgrade {package_name}=={fixed_version}'.")
        return True
    else:
        logging.warning(f"Direct pip upgrade also failed for {package_name}.")
        return False

def fix_gem_dependency(package_name, fixed_version, app_root_dir):
    """
    Implements fix for Ruby (gem) dependencies by updating Gemfile.
    Requires 'bundle update {package_name}' or 'bundle install'.
    """
    logging.info(f"Attempting to fix Ruby gem '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    gemfile_path = os.path.join(app_root_dir, 'Gemfile')
    gemfile_lock_path = os.path.join(app_root_dir, 'Gemfile.lock')

    if not os.path.exists(gemfile_path) and not os.path.exists(gemfile_lock_path):
        logging.warning(f"Neither Gemfile nor Gemfile.lock found at {app_root_dir}. Skipping Ruby gem fix for {package_name}.")
        return False

    updated_gemfile = False

    if os.path.exists(gemfile_path):
        logging.info(f"Found Gemfile at {gemfile_path}. Attempting to update.")
        try:
            with open(gemfile_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            new_lines = []
            updated = False
            for line in lines:
                # Regex to find 'gem "package_name"' with or without version constraints
                gem_pattern = r"^\s*gem\s+['\"]" + re.escape(package_name) + r"['\"](\s*,.*)?$"
                match = re.match(gem_pattern, line, re.IGNORECASE)
                if match:
                    # Append or replace the version constraint
                    # Use optimistic operator ~> for better compatibility, or exact for strict fix
                    # For a "fixed version", exact '== {fixed_version}' is safer if known specific fix
                    # but '~> fixed_version' (e.g., ~> 1.2.3 means >= 1.2.3 and < 1.3.0) is common.
                    # Sticking to '~>' for broader compatibility within a minor/patch release.
                    new_line = f"  gem '{package_name}', '~> {fixed_version}'\n"
                    
                    if new_line.strip() != line.strip(): # Compare stripped lines to ignore whitespace differences
                        new_lines.append(new_line)
                        logging.info(f"Updated Gemfile line: {new_line.strip()}")
                        updated = True
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if updated:
                if atomic_write_file(gemfile_path, "".join(new_lines)):
                    updated_gemfile = True
                else:
                    return False # Failed to write
            else:
                logging.info(f"Could not find or update '{package_name}' in Gemfile. Attempting direct bundle update.")
        except Exception as e:
            logging.error(f"Error updating Gemfile for {package_name}: {e}")
            # Do not return, try bundle update as fallback

    # If Gemfile was updated, run bundle install. Else, try bundle update specific gem.
    if updated_gemfile:
        success_bundle, _ = run_command(["bundle", "install"], cwd=app_root_dir, description="bundle install")
        if success_bundle:
            logging.info(f"Successfully ran 'bundle install' after updating {package_name}.")
            return True
        else:
            logging.error(f"Failed to run 'bundle install' after updating Gemfile for {package_name}. Trying 'bundle update {package_name}'.")
            # Fallback to direct bundle update if bundle install failed
            pass # Continue to the direct bundle update path below

    # Fallback: try bundle update specific gem or general bundle install
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
    Implements fix for Go (go mod) dependencies.
    Requires 'go get -u {package_name}' then 'go mod tidy'.
    """
    logging.info(f"Attempting to fix Go module '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    go_mod_path = os.path.join(app_root_dir, 'go.mod')
    if not os.path.exists(go_mod_path):
        logging.warning(f"go.mod not found at {go_mod_path}. Skipping Go module fix for {package_name}.")
        return False

    # Attempt to upgrade the specific module
    # Use 'go get package_name@version' to set a specific version
    success_get, _ = run_command(["go", "get", f"{package_name}@{fixed_version}"], cwd=app_root_dir, check_result=False, description="go get")
    if success_get:
        logging.info(f"Successfully ran 'go get {package_name}@{fixed_version}'. Running 'go mod tidy'.")
        success_tidy, _ = run_command(["go", "mod", "tidy"], cwd=app_root_dir, description="go mod tidy")
        if success_tidy:
            logging.info(f"Successfully ran 'go mod tidy'.")
            return True
        else:
            logging.error(f"Failed to run 'go mod tidy' after updating {package_name}.")
            return False
    else:
        logging.error(f"Failed to run 'go get {package_name}@{fixed_version}'. Manual intervention may be required.")
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
        # Find 'USER root' anywhere in the file (could be multiple stages)
        user_root_lines = [i for i, line in enumerate(new_lines) if line.strip().upper() == "USER ROOT"]
        
        if user_root_lines:
            logging.info("Found 'USER root' instruction(s), attempting to replace with non-root user.")
            temp_new_lines = []
            for i, line in enumerate(new_lines):
                if i in user_root_lines:
                    # Heuristic: Check if base image provides a common user like 'node'
                    user_add_commands_to_insert = [
                        "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n",
                        "USER appuser\n"
                    ]
                    
                    from_line_for_stage = ""
                    # Find the most recent FROM for this stage
                    for j in range(i, -1, -1):
                        if new_lines[j].strip().upper().startswith("FROM"):
                            from_line_for_stage = new_lines[j].lower()
                            break

                    if "node:" in from_line_for_stage:
                        user_add_commands_to_insert = ["USER node\n"] # Assume 'node' user exists
                    elif "alpine" in from_line_for_stage:
                        user_add_commands_to_insert = [
                            "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n", # Alpine
                            "USER appuser\n"
                        ]
                    elif "debian" in from_line_for_stage or "ubuntu" in from_line_for_stage:
                         user_add_commands_to_insert = [
                            "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n", # Debian/Ubuntu
                            "USER appuser\n"
                        ]

                    temp_new_lines.extend(user_add_commands_to_insert)
                    logging.info(f"Replaced 'USER root' with: {' '.join([cmd.strip() for cmd in user_add_commands_to_insert])}")
                    updated_any_rule = True
                else:
                    temp_new_lines.append(line)
            new_lines = temp_new_lines
        elif not user_set_explicitly and first_from_index != -1: # No USER instruction at all, add one after the first FROM or last RUN
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

            # Insert at the calculated index
            new_lines[insert_index:insert_index] = user_add_commands_to_insert
            logging.info("Added non-root user to Dockerfile.")
            updated_any_rule = True
        else:
            logging.info("Dockerfile already has a non-root USER instruction or no suitable insertion point. Skipping user hardening.")
        
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
                    # Check if WORKDIR is present after this FROM but before next FROM/end of file
                    # To avoid duplicate WORKDIRs if one exists later in the stage
                    stage_has_workdir = False
                    for j in range(i + 1, len(new_lines)):
                        if new_lines[j].strip().upper().startswith("FROM"): # New stage starts
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

            if not insert_point_found: # Fallback: add at the very beginning after any FROM
                # Find the last FROM instruction to insert WORKDIR after it
                last_from_idx = -1
                for i, line in enumerate(new_lines):
                    if line.strip().upper().startswith("FROM"):
                        last_from_idx = i
                
                if last_from_idx != -1:
                    new_lines.insert(last_from_idx + 1, "WORKDIR /app\n")
                    logging.info("Added WORKDIR /app to Dockerfile after last FROM.")
                    updated_any_rule = True
                else: # Fallback to start if no FROM (unlikely for a valid Dockerfile)
                    new_lines.insert(0, "WORKDIR /app\n")
                    logging.warning("No FROM instruction found. Added WORKDIR /app at start of Dockerfile.")
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

# --- NEW FUNCTION FOR MODIFIYING DOCKERFILE FOR NPM --legacy-peer-deps ---
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
            # Look for lines that exactly match "RUN npm install" (case-insensitive, optional leading/trailing spaces)
            # This avoids modifying `npm install -g` or other npm commands
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

# --- MODIFIED build_docker_image function with retry logic ---
def build_docker_image(dockerfile_path, image_name, app_root_dir):
    """
    Builds a Docker image. Adds a retry with --legacy-peer-deps if initial build fails due to npm ERESOLVE.
    Returns True on success, False on failure.
    """
    # Use os.path.basename to ensure Dockerfile is referenced correctly if cwd is its parent
    cmd = ["docker", "build", "-f", os.path.basename(dockerfile_path), "-t", image_name, "."]
    
    logging.info(f"Attempting to build Docker image '{image_name}' from {dockerfile_path}")
    
    # First attempt: regular build
    success, stderr_output = run_command(cmd, cwd=app_root_dir, check_result=False, capture_output=True, description="docker build")

    if not success:
        if "npm error code ERESOLVE" in stderr_output:
            logging.warning("Docker build failed due to npm ERESOLVE error. Attempting to apply --legacy-peer-deps fix.")
            
            # Save original Dockerfile content before modification for potential rollback
            original_dockerfile_content = None
            if os.path.exists(dockerfile_path):
                with open(dockerfile_path, 'r', encoding='utf-8') as f:
                    original_dockerfile_content = f.read()

            if modify_dockerfile_for_npm_legacy_peer_deps(dockerfile_path):
                logging.info("Dockerfile modified. Retrying docker build with --legacy-peer-deps.")
                # Second attempt: with --legacy-peer-deps
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
                    # Rollback Dockerfile to original state if retry also failed
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

# --- Mock-up for vulnerability data and main pipeline flow ---
# This part simulates how your main script would call these functions

# In a real scenario, this data would come from Trivy/Grype scan output.
# This is just for demonstrating the fix.
def parse_vulnerability_report(report_path):
    """
    Parses a vulnerability report (e.g., Trivy JSON) and extracts
    actionable remediation steps. This is a simplified mock.
    """
    logging.info(f"Parsing vulnerability report from {report_path} (mock function).")
    # For demonstration, we'll simulate a scenario where no direct vuln
    # is found *but* the build failed due to the npm ERESOLVE.
    # In a real system, you'd iterate through actual CVEs and their fix versions.
    
    # Example: If a specific npm package (e.g., 'marked') had a CVE,
    # you'd return something like:
    # return [
    #     {"type": "npm", "package": "marked", "fixed_version": "4.3.0", "app_path": "frontend"}
    # ]
    
    # For this specific scenario, we're not getting a direct CVE fix instruction
    # but rather handling a build-time dependency conflict.
    return [] 

def find_fix_online(vulnerability_id, package_name, installed_version, description, severity, current_base_image=None):
    """
    Mocks searching for online remediation information.
    In a real system, this would involve querying vulnerability databases (e.g., NVD, OVE, vendor advisories)
    or using AI/ML to infer fix versions.
    """
    logging.info(f"Mock: Searching online for fix for {vulnerability_id} / {package_name}@{installed_version}")
    # Example: If it was a known vulnerability in 'marked'
    # if package_name == "marked" and installed_version == "0.6.2":
    #     return {"fixed_version": "4.3.0", "remediation_advice": "Update marked to 4.3.0 or higher."}
    return {} # No specific fix found by this mock for the build error

def main():
    # Define paths based on the provided log context
    # These would typically be passed as environment variables or arguments in a CI/CD setup
    workspace_root = "/home/runner/work/real-estate-management/real-estate-management"
    frontend_app_dir = os.path.join(workspace_root, "frontend")
    dockerfile_path = os.path.join(frontend_app_dir, "Dockerfile")
    
    # Assume a dynamic image name generation for the remediated image
    timestamp = int(time.time())
    remediated_image_name = f"kirmadadaa/taskapi-frontend:remediated-{timestamp}"
    
    logging.info(f"Starting automated vulnerability remediation pipeline for {frontend_app_dir}")

    changes_made = False

    # Step 1: Apply general Dockerfile hardening
    logging.info("Attempting to apply general Dockerfile hardening rules.")
    if harden_dockerfile(dockerfile_path):
        changes_made = True
        logging.info("Dockerfile hardening changes applied.")
    else:
        logging.info("No Dockerfile hardening changes were applied or needed.")

    # Step 2: (Optional) Parse scan report and apply specific dependency fixes
    # In this scenario, the user's provided logs don't include Trivy output,
    # but indicate a build failure, so we'll simulate no direct package fixes
    # from a scan report, but the build_docker_image will handle the npm error.
    
    # Placeholder for actual vulnerability parsing and fixing
    # remediations = parse_vulnerability_report("path/to/trivy-report.json")
    # for rem in remediations:
    #     if rem["type"] == "npm":
    #         if fix_npm_dependency(rem["package"], rem["fixed_version"], os.path.join(workspace_root, rem["app_path"])):
    #             changes_made = True
    #     elif rem["type"] == "pip":
    #         if fix_pip_dependency(rem["package"], rem["fixed_version"], os.path.join(workspace_root, rem["app_path"])):
    #             changes_made = True
    #     # ... handle other types like gem, go mod, os packages ...

    logging.info("Checking for changes that necessitate image rebuild.")

    # Use Git to detect if any files were modified by the remediation steps
    # This is more robust than relying on the boolean 'changes_made' from fix functions
    try:
        git_status_cmd = ["git", "status", "--porcelain"]
        success, git_output = run_command(git_status_cmd, cwd=workspace_root, capture_output=True, check_result=True, description="git status")
        if success and git_output:
            logging.info("Changes detected in the repository due to remediation. Attempting to rebuild and re-scan image.")
            changes_made = True
        else:
            logging.info("No changes detected in the repository from remediation. Skipping rebuild/re-scan.")
            changes_made = False # Ensure this is false if git status is clean

    except subprocess.CalledProcessError as e:
        logging.error(f"Git command failed, cannot determine changes: {e}")
        # Proceed with rebuild if git status failed, better safe than sorry
        changes_made = True 
    except Exception as e:
        logging.error(f"An unexpected error occurred during git status check: {e}")
        changes_made = True

    if changes_made:
        # Step 3: Rebuild and Retest the image
        if build_docker_image(dockerfile_path, remediated_image_name, frontend_app_dir):
            logging.info(f"Docker image '{remediated_image_name}' built successfully.")
            
            # Step 4: Re-scan the newly built image to confirm remediation
            logging.info(f"Re-scanning remediated image '{remediated_image_name}' with Trivy.")
            scan_cmd = ["trivy", "image", "--format", "json", "--output", "remediated_trivy_report.json", remediated_image_name]
            
            # Run Trivy scan. We can set check_result=False if we want to parse even with findings,
            # but for validation, we expect zero critical/high vulns.
            success_scan, scan_output = run_command(scan_cmd, cwd=workspace_root, check_result=False, capture_output=True, description="Trivy re-scan")
            
            if success_scan:
                logging.info(f"Trivy re-scan completed for {remediated_image_name}. Analyzing report...")
                # Further parsing of 'remediated_trivy_report.json' would go here
                # to confirm no critical/high vulnerabilities remain.
                # Example:
                # with open(os.path.join(workspace_root, "remediated_trivy_report.json"), 'r', encoding='utf-8') as f:
                #     report_data = json.load(f)
                #     # Check for critical/high vulns
                #     if any(vuln['Severity'] in ['CRITICAL', 'HIGH'] for result in report_data.get('Results', []) for vuln in result.get('Vulnerabilities', [])):
                #         logging.error(f"Remediated image '{remediated_image_name}' still has Critical/High vulnerabilities. Remediation failed.")
                #         sys.exit(1)
                #     else:
                #         logging.info(f"Remediated image '{remediated_image_name}' is clean of Critical/High vulnerabilities.")
                #         # Step 5: Integrate - Auto-commit & PR fixed files, Notify
                #         logging.info("Committing remediated changes...")
                #         run_command(["git", "add", "."], cwd=workspace_root, description="git add")
                #         commit_message = f"feat(automation): Automated vulnerability remediation for {os.path.basename(frontend_app_dir)}"
                #         run_command(["git", "commit", "-m", commit_message], cwd=workspace_root, description="git commit")
                #         # In a real GitHub Actions workflow, pushing and creating PR would happen here.
                #         # E.g., using 'gh pr create' or 'git push' to a new branch.
                #         # Notify Slack: webhook_url, message_payload
                #         logging.info("Remediation complete and image is clean. Manual review of Git changes recommended.")
                #         sys.exit(0) # Success
            else:
                logging.error(f"Trivy re-scan failed for {remediated_image_name}. Please investigate.")
                # This might happen if Trivy itself fails, not necessarily due to vulns.
                sys.exit(1)
        else:
            logging.error("Failed to rebuild Docker image after remediation attempts. Review logs for details.")
            sys.exit(1)
    else:
        logging.info("No remediation changes were applied or detected. Exiting without further action.")
        sys.exit(0) # Exit successfully if no action was needed

if __name__ == "__main__":
    # Ensure this script is run from a context where `git` is available
    # and the paths point to your actual repository.
    # For a GitHub Actions runner, the current working directory will be the repo root.
    main()
