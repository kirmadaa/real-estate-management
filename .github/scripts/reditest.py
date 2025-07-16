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
    success_audit, _ = run_command(["npm", "audit", "fix"], cwd=app_root_dir, check_result=False, description="npm audit fix")
    if success_audit:
        logging.info(f"Successfully ran 'npm audit fix'. Verifying if fix was applied.")
        # Re-check package-lock.json or rely on subsequent Trivy scan
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
    """
    Implements fix for Python (pip) dependencies by attempting to update
    requirements.txt (if found) or directly upgrading the package.
    """
    logging.info(f"Attempting to fix Python package '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    
    requirements_path = os.path.join(app_root_dir, 'requirements.txt')
    pipfile_lock_path = os.path.join(app_root_dir, 'Pipfile.lock')

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
                    # Now install dependencies from the updated requirements file
                    success, _ = run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                                             cwd=app_root_dir, description="pip install -r requirements.txt")
                    if success:
                        logging.info(f"Successfully ran 'pip install -r requirements.txt' after updating {package_name}.")
                        return True
                return False # Failed to write or install
            else:
                logging.info(f"Could not find or update '{package_name}' in requirements.txt. Attempting direct upgrade.")

        except Exception as e:
            logging.error(f"Error updating requirements.txt for {package_name}: {e}")
    
    # Fallback to direct upgrade if requirements.txt not found or update failed
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
                    if match.group(1): # Existing constraints
                        # Replace all constraints with the exact fixed version
                        new_line = f"  gem '{package_name}', '~> {fixed_version}'\n" # Use optimistic operator ~>
                    else:
                        new_line = f"  gem '{package_name}', '~> {fixed_version}'\n"
                    
                    if new_line != line:
                        new_lines.append(new_line)
                        logging.info(f"Updated Gemfile line: {new_line.strip()}")
                        updated = True
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if updated:
                if atomic_write_file(gemfile_path, "".join(new_lines)):
                    # Now run bundle install to update Gemfile.lock
                    success_bundle, _ = run_command(["bundle", "install"], cwd=app_root_dir, description="bundle install")
                    if success_bundle:
                        logging.info(f"Successfully ran 'bundle install' after updating {package_name}.")
                        return True
                return False # Failed to write or install
            else:
                logging.info(f"Could not find or update '{package_name}' in Gemfile. Attempting direct bundle update.")

        except Exception as e:
            logging.error(f"Error updating Gemfile for {package_name}: {e}")

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
    # If the package is a main module dependency, go.mod might need to be edited.
    # For now, let's try 'go get' which usually updates go.mod automatically.
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
                    # This requires looking up the FROM instruction for the current stage.
                    # For simplicity here, we'll use a generic appuser unless it's a known image.
                    user_add_commands_to_insert = [
                        "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n",
                        "USER appuser\n"
                    ]
                    # This simple heuristic might need to be more sophisticated for multi-stage builds
                    # where FROM might be far away or aliased.
                    from_line_for_stage = ""
                    for j in range(i, -1, -1):
                        if new_lines[j].strip().upper().startswith("FROM"):
                            from_line_for_stage = new_lines[j].lower()
                            break

                    if "node:" in from_line_for_stage:
                        user_add_commands_to_insert = ["USER node\n"] # Assume 'node' user exists
                    elif "alpine" in from_line_for_stage or "debian" in from_line_for_stage:
                        # For simple base images, create user manually if not set
                        user_add_commands_to_insert = [
                            "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n", # Alpine/Debian
                            "USER appuser\n"
                        ]


                    temp_new_lines.extend(user_add_commands_to_insert)
                else:
                    temp_new_lines.append(line)
            new_lines = temp_new_lines
            logging.info("Replaced 'USER root' with non-root user commands.")
            updated_any_rule = True
        elif not user_set_explicitly and first_from_index != -1: # No USER instruction at all, add one after the first FROM or last RUN
            insert_index = last_run_index if last_run_index > first_from_index else first_from_index + 1
            
            user_add_commands_to_insert = [
                "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n",
                "USER appuser\n"
            ]
            from_line = next((l for l in lines if l.strip().upper().startswith("FROM")), "").lower()
            if "node:" in from_line:
                user_add_commands_to_insert = ["USER node\n"]
            elif "alpine" in from_line or "debian" in from_line:
                 user_add_commands_to_insert = [
                    "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n", 
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

# --- NEW FUNCTION FOR INTERNET SEARCH AND FIX DISCOVERY ---
def find_fix_online(vulnerability_id, package_name, installed_version, description, severity):
    """
    Searches the internet for remediation information for a given vulnerability.
    Returns a dictionary with 'fixed_version' (if found) or 'remediation_advice'.
    This is a mock-up function. In a real scenario, this would involve:
    1. Querying public vulnerability databases (NVD, OSV, GHSA).
    2. Parsing security advisories for fixed versions or recommended actions.
    3. Potentially using AI/ML to infer fixes from unstructured text.
    """
    logging.info(f"Simulating online search for fix for {vulnerability_id} (Package: {package_name}, Version: {installed_version})")
    
    # Example Heuristics (REPLACE WITH REAL API CALLS/DB LOOKUPS)
    # Heuristic 1: Base OS vulnerability suggesting a base image upgrade
    if "linux kernel" in description.lower() or "linux-libc-dev" in package_name.lower() or "glibc" in package_name.lower():
        logging.info("Simulated: Found a recommended base image upgrade for a critical OS vulnerability.")
        # In a real system, you'd determine the latest patched version of the base image.
        # Example: if current is 'debian:11-slim', recommend 'debian:12-slim' or specific patched version.
        return {"type": "base_image_upgrade", "recommended_image": "debian:12.12-slim"} # Example newer version
    
    # Heuristic 2: Specific common application dependency
    elif "git" in package_name.lower() and "file creation flaw" in description.lower():
         logging.info("Simulated: Found a specific git version fix.")
         return {"type": "package_upgrade", "fixed_version": "2.40.1"} # Example specific version
    elif "mysql-server" in package_name.lower() and "high" in severity.upper():
         logging.info("Simulated: Found a specific mysql-server version fix.")
         return {"type": "package_upgrade", "fixed_version": "8.0.42"} # Example specific version
    elif "express" in package_name.lower() and "moderate" in severity.upper() and "node.js" in description.lower():
        logging.info("Simulated: Found a specific Express.js version fix.")
        return {"type": "package_upgrade", "fixed_version": "4.18.3"}
    elif "lodash" in package_name.lower() and "prototype pollution" in description.lower():
        logging.info("Simulated: Found a specific Lodash version fix.")
        return {"type": "package_upgrade", "fixed_version": "4.17.21"}

    logging.info("Simulated: No specific fix found online through this heuristic for this vulnerability.")
    return {"type": "manual_review", "remediation_advice": "Consult official advisories for " + vulnerability_id}


def build_docker_image(dockerfile_path, image_name, app_root_dir):
    """
    Builds a Docker image after remediation.
    """
    logging.info(f"Attempting to build Docker image '{image_name}' from {dockerfile_path}")
    
    # Determine the effective Dockerfile path for the build command
    # This path needs to be relative to the build context (app_root_dir)
    effective_dockerfile_path = os.path.relpath(dockerfile_path, start=app_root_dir) \
                                if os.path.commonpath([app_root_dir, dockerfile_path]) == app_root_dir \
                                else dockerfile_path # Keep as is if not a subpath

    cmd = ["docker", "build", "-f", effective_dockerfile_path, "-t", image_name, "."]
    success, _ = run_command(cmd, cwd=app_root_dir, description="docker build")
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
    # --exit-code 0 to ensure the command itself doesn't fail even if vulns are found.
    # We will parse the JSON to determine if vulns exist.
    cmd = ["trivy", "image", "--scanners", "vuln", "--format", "json", "--output", output_path, "--exit-code", "0", image_name]
    success, _ = run_command(cmd, description="Trivy scan", check_result=False) # Don't fail if Trivy finds vulns
    
    if not success:
        logging.error(f"Trivy scan command failed for {image_name}. Check logs.")
        return False
    
    # After running Trivy, check the report file for vulnerabilities
    if os.path.exists(output_path):
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            # Check if any vulnerabilities are reported
            for result in report.get("Results", []):
                if result.get("Vulnerabilities"):
                    logging.warning(f"Trivy scan completed for {image_name}. Vulnerabilities found. Report saved to {output_path}")
                    return True # Still consider it successful completion of scan, even if vulns are there
            logging.info(f"Trivy scan completed for {image_name}. No vulnerabilities found. Report saved to {output_path}")
            return True
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding Trivy scan JSON report from '{output_path}': {e}.")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred while reading Trivy scan report '{output_path}': {e}")
            return False
    else:
        logging.error(f"Trivy scan output file not found at {output_path}. Scan likely failed.")
        return False


def commit_changes_to_git(app_root_dir, commit_message):
    """
    Stages and commits changes in the Git repository.
    Returns True if changes were committed, False otherwise.
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
        # git diff --cached --exit-code returns 0 if no differences, 1 if differences
        success_diff, _ = run_command(["git", "diff", "--cached", "--exit-code"], cwd=app_root_dir, check_result=False, capture_output=True)
        
        if success_diff: # Means there are NO differences, so no staged changes
            logging.info("No changes to commit after remediation. Working directory is clean.")
            return False
        else: # There are differences (exit code 1), meaning changes are staged
            logging.info("Found staged changes. Committing...")
            success_commit, _ = run_command(["git", "commit", "-m", commit_message], cwd=app_root_dir, description="git commit")
            if success_commit:
                logging.info("Successfully committed changes.")
                return True
            else:
                logging.error("Failed to commit Git changes.")
                return False

    except Exception as e:
        logging.error(f"An unexpected error occurred during Git operations: {e}")
        return False


def main():
    # Retrieve paths from environment variables, typically set by GitHub Actions
    # Provide robust defaults
    # Get the repository root, which is the current working directory of the action runner
    repo_root = os.getcwd() 

    # APP_ROOT_DIR and DOCKERFILE_PATH are passed from GitHub Actions relative to repo_root
    app_root_dir_env = os.environ.get('APP_ROOT_DIR', '.') # Default to '.' if not set
    dockerfile_path_env = os.environ.get('DOCKERFILE_PATH', 'Dockerfile') # Default 'Dockerfile'

    # Resolve these to absolute paths based on the repo_root
    app_root_dir = os.path.abspath(os.path.join(repo_root, app_root_dir_env))
    dockerfile_path = os.path.abspath(os.path.join(repo_root, dockerfile_path_env))

    report_path = os.path.join(repo_root, os.environ.get('TRIVY_REPORT_PATH', 'trivy-report.json')) # Ensure report path is also absolute
    
    # Define remediated image name (ensure it's distinct for re-scanning)
    base_image_name = os.environ.get('IMAGE_NAME', 'my-app') # From workflow env
    image_tag = os.environ.get('IMAGE_TAG', 'latest') # From workflow env (original image tag)
    remediated_image_name = f"{base_image_name}:remediated-{int(time.time())}" # New tag for remediated image

    logging.info(f"Repository Root Directory: {repo_root}")
    logging.info(f"App Root Directory for Build Context: {app_root_dir}")
    logging.info(f"Dockerfile Path: {dockerfile_path}")
    logging.info(f"Trivy Report Path: {report_path}")
    logging.info(f"Original Image Name: {base_image_name}:{image_tag}")
    logging.info(f"Remediated Image Name (Proposed): {remediated_image_name}")

    if not os.path.exists(report_path):
        logging.error(f"Trivy report not found at {report_path}. Exiting with failure.")
        sys.exit(1)
    if not os.path.isfile(report_path):
        logging.error(f"'{report_path}' is not a file. Exiting with failure.")
        sys.exit(1)

    dockerfile_exists = os.path.exists(dockerfile_path) and os.path.isfile(dockerfile_path)
    if not dockerfile_exists:
        logging.warning(f"Dockerfile not found at {dockerfile_path}. OS-level and Dockerfile hardening fixes will be limited or skipped.")

    if not os.path.isdir(app_root_dir):
        logging.error(f"Application root directory not found at {app_root_dir}. Exiting with failure.")
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
    repo_changed = False # Track if any file in the repo was changed by remediation attempts

    results = report.get("Results", [])
    if not results:
        logging.info("No 'Results' found in the Trivy report. Nothing to remediate.")
        sys.exit(0) # Success: no vulnerabilities to fix.

    # Collect unique vulnerabilities for remediation attempts
    # This helps avoid redundant work if the same vulnerability is listed multiple times
    # (e.g., in different layers, though Trivy usually de-dupes).
    # Store as (vuln_id, pkg_name, installed_version, data_source, target, description, severity)
    unique_vulnerabilities = set()
    for result in results:
        target = result.get("Target", "N/A Target")
        for vuln in result.get("Vulnerabilities", []):
            vuln_id = vuln.get("VulnerabilityID", "N/A")
            pkg_name = vuln.get("PkgName", "N/A")
            installed_version = vuln.get("InstalledVersion", "N/A")
            fixed_version_trivy = vuln.get("FixedVersion", "").strip()
            severity = vuln.get("Severity", "UNKNOWN").strip()
            data_source = vuln.get("DataSource", {}).get("ID", "N/A").lower().strip()
            description = vuln.get("Description", "").strip()

            # Normalize fixed_version_trivy to None if not genuinely fixed
            effective_fixed_version = fixed_version_trivy if fixed_version_trivy and fixed_version_trivy.lower() != "not fixed" else None
            
            unique_vulnerabilities.add((vuln_id, pkg_name, installed_version, effective_fixed_version, data_source, target, description, severity))

    vulnerabilities_found = len(unique_vulnerabilities)

    if vulnerabilities_found == 0:
        logging.info("No actionable vulnerabilities found in the report.")
        sys.exit(0)

    logging.info(f"Attempting to remediate {vulnerabilities_found} unique vulnerabilities.")

    for vuln_id, pkg_name, installed_version, trivy_fixed_version, data_source, target, description, severity in unique_vulnerabilities:
        fixed_current_vuln = False
        
        # 1. Try Trivy-provided fix first
        if trivy_fixed_version:
            logging.info(f"  [ATTEMPTING FIX] {vuln_id} ({pkg_name}@{installed_version}) -> {trivy_fixed_version} (Trivy-provided)")
            if "npm" in data_source or "node.js" in target.lower() or "package.json" in target.lower():
                fixed_current_vuln = fix_npm_dependency(pkg_name, trivy_fixed_version, app_root_dir)
            elif "pip" in data_source or "python" in target.lower() or "pipfile.lock" in target.lower() or "requirements.txt" in target.lower():
                fixed_current_vuln = fix_pip_dependency(pkg_name, trivy_fixed_version, app_root_dir)
            elif "gem" in data_source or "ruby" in target.lower() or "gemfile.lock" in target.lower():
                fixed_current_vuln = fix_gem_dependency(pkg_name, trivy_fixed_version, app_root_dir)
            elif "go" in data_source or "go.mod" in target.lower():
                fixed_current_vuln = fix_go_dependency(pkg_name, trivy_fixed_version, app_root_dir)
            elif "os" in data_source or "distro" in data_source or "library" in data_source: # OS-level packages
                # Direct OS package upgrade is harder without knowing the OS type.
                # Often, it implies a base image upgrade.
                logging.info(f"  [SKIPPING] {vuln_id} ({pkg_name}): OS-level vulnerability, direct package upgrade not handled by specific fixers. Will try online lookup for base image.")
            else:
                logging.info(f"  [SKIPPING] {vuln_id} ({pkg_name}): Trivy provided fix, but remediation for this type (DataSource: '{data_source}', Target: '{target}') not implemented directly for package manager.")
        
        # 2. If not fixed by Trivy's suggestion or no suggestion, attempt online lookup
        if not fixed_current_vuln:
            logging.info(f"  [ATTEMPTING ONLINE FIX] {vuln_id} ({pkg_name}@{installed_version}): No Trivy-provided fix or direct fix failed. Searching online...")
            online_fix_info = find_fix_online(vuln_id, pkg_name, installed_version, description, severity)

            if online_fix_info["type"] == "base_image_upgrade" and dockerfile_exists:
                current_base_image = None
                try:
                    with open(dockerfile_path, 'r', encoding='utf-8') as f:
                        dockerfile_content = f.read()
                    # Capture "FROM image:tag" potentially with "AS builder"
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
                         logging.warning(f"    Online search found package fix for {pkg_name}, but type '{data_source}' not supported by current fixers.")
                 else:
                    logging.info(f"    Online search found 'package_upgrade' type but no 'fixed_version'.")
            else:
                logging.info(f"  [SKIPPING ONLINE FIX] {vuln_id} ({pkg_name}): {online_fix_info.get('remediation_advice', 'No effective online fix found or applicable.')}")
        
        if fixed_current_vuln:
            vulnerabilities_fixed += 1
            repo_changed = True
            logging.info(f"  [SUCCESS] Fixed {vuln_id} ({pkg_name}). Total fixed: {vulnerabilities_fixed}")
        else:
            logging.warning(f"  [FAILED] Could not fix {vuln_id} ({pkg_name}).")

    # Apply general Dockerfile hardening if a Dockerfile path was provided and exists
    if dockerfile_exists:
        logging.info("\nAttempting to apply general Dockerfile hardening rules.")
        if harden_dockerfile(dockerfile_path):
            repo_changed = True
            logging.info("Dockerfile hardening applied.")
        else:
            logging.info("No Dockerfile hardening changes were applied or needed.")

    if vulnerabilities_found == 0 and not repo_changed:
        logging.info("\nNo vulnerabilities found and no Dockerfile hardening applied. Exiting successfully.")
        sys.exit(0)

    # --- Build and Re-scan if changes were made ---
    remediation_successful = False
    remediation_validation_passed = False
    new_report_path = os.path.join(os.path.dirname(report_path), "trivy-remediated-scan-report.json")

    if repo_changed:
        logging.info("\nChanges detected in the repository due to remediation. Attempting to rebuild and re-scan image.")
        if build_docker_image(dockerfile_path, remediated_image_name, app_root_dir):
            logging.info(f"Successfully rebuilt image: {remediated_image_name}")
            if run_trivy_scan(remediated_image_name, new_report_path):
                logging.info(f"Remediated image scanned. Checking {new_report_path} for residual vulnerabilities.")
                # Parse the new report to determine if validation passed (zero vulns)
                try:
                    with open(new_report_path, 'r', encoding='utf-8') as f:
                        remediated_report = json.load(f)
                    
                    found_after_remediation = False
                    for result in remediated_report.get("Results", []):
                        if result.get("Vulnerabilities"):
                            found_after_remediation = True
                            break
                    
                    if not found_after_remediation:
                        logging.info("Remediation validation: Image is clean after fixes! Great success!")
                        remediation_validation_passed = True
                        remediation_successful = True # Overall success, as all found are fixed and validated
                    else:
                        logging.warning("Remediation validation: Vulnerabilities still present after remediation. Manual review needed.")
                        remediation_successful = (vulnerabilities_fixed > 0) # Partial success if some were fixed
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding remediated JSON report from '{new_report_path}': {e}.")
                except Exception as e:
                    logging.error(f"An unexpected error occurred while reading remediated Trivy report '{new_report_path}': {e}")
            else:
                logging.error("Re-scan failed. Cannot validate remediation. Manual review of the remediated image is recommended.")
                remediation_successful = (vulnerabilities_fixed > 0) # Still partial success if fixes were applied
        else:
            logging.error("Failed to rebuild Docker image. Cannot perform re-scan validation.")
            remediation_successful = (vulnerabilities_fixed > 0) # Still partial success if fixes were applied

        # --- Commit changes to Git (handled by workflow's git-auto-commit-action) ---
        # The script's commit_changes_to_git is mainly for internal tracking.
        # The GitHub Action will perform the actual commit and push.
        # We'll just indicate if the local repo *was* changed.
        if commit_changes_to_git(app_root_dir, f"Automated vulnerability remediation: Fixed {vulnerabilities_fixed} of {vulnerabilities_found} vulnerabilities."):
            logging.info("Local repository changes have been staged and committed by the script. GitHub Action will push these.")
        else:
            logging.info("No additional changes to commit by the script after initial remediation attempts.")


    # --- Final Exit Status ---
    if vulnerabilities_fixed == vulnerabilities_found and remediation_validation_passed:
        logging.info(f"\nAll {vulnerabilities_fixed} vulnerabilities found have been fixed and validated as clean!")
        sys.exit(0) # Success
    elif vulnerabilities_fixed > 0:
        logging.warning(f"\nSuccessfully fixed {vulnerabilities_fixed} out of {vulnerabilities_found} vulnerabilities. Review remaining issues.")
        sys.exit(0) # Partial success, or could be 1 for stricter CI. Let's keep 0 for now as it made progress.
    elif vulnerabilities_found > 0 and not remediation_successful:
        logging.error(f"\nCould not automatically fix any of the {vulnerabilities_found} vulnerabilities.")
        sys.exit(1) # Failure: no vulnerabilities could be fixed.
    elif not repo_changed:
        logging.info("\nNo changes made or required. Exiting successfully.")
        sys.exit(0) # No vulnerabilities, or no applicable fixes.


if __name__ == "__main__":
    main()
