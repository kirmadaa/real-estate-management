import json
import os
import re
import subprocess
import sys

def run_command(cmd, cwd=None, check_result=True, capture_output=False):
    """Helper to run shell commands."""
    print(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, cwd=cwd, check=check_result,
                                capture_output=capture_output, text=True)
        if capture_output:
            return result.stdout.strip()
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        if capture_output:
            print(f"Stdout: {e.stdout}")
            print(f"Stderr: {e.stderr}")
        # Re-raise the exception to indicate failure for the simulation
        raise
    except FileNotFoundError:
        print(f"Command not found: {cmd[0]}. Please ensure it's installed and in PATH.")
        # In a real scenario, sys.exit(1) would be here to fail the CI step
        raise

def update_dockerfile_base_image(dockerfile_path, current_image, fixed_image):
    """Updates the base image in a Dockerfile."""
    print(f"Attempting to update base image in {dockerfile_path} from {current_image} to {fixed_image}")
    try:
        if not os.path.exists(dockerfile_path):
            print(f"Dockerfile '{dockerfile_path}' not found for update.")
            return False

        with open(dockerfile_path, 'r') as f:
            lines = f.readlines()

        new_lines = []
        updated = False
        for line in lines:
            if line.strip().upper().startswith("FROM"):
                # Use regex to replace the image name and tag safely
                # This assumes the 'FROM' line contains the full image:tag
                if current_image in line:
                    new_line = line.replace(current_image, fixed_image)
                    new_lines.append(new_line)
                    print(f"Updated FROM line: {new_line.strip()}")
                    updated = True
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        if updated:
            with open(dockerfile_path, 'w') as f:
                f.writelines(new_lines)
            print(f"Dockerfile '{dockerfile_path}' base image updated successfully.")
            return True
        else:
            print(f"Could not find '{current_image}' in Dockerfile '{dockerfile_path}' to update.")
            return False
    except Exception as e:
        print(f"Error updating Dockerfile base image: {e}")
        return False

def fix_npm_dependency(package_name, fixed_version, app_root_dir):
    """
    Fixes a specific NPM package dependency by running npm commands
    in the specified application root directory.
    """
    print(f"Attempting to fix NPM package '{package_name}' to version '{fixed_version}' in {app_root_dir}")
    
    package_json_path = os.path.join(app_root_dir, 'package.json')
    if not os.path.exists(package_json_path):
        print(f"Error: package.json not found at {package_json_path} for NPM fix.")
        return False

    # Attempt npm update first
    try:
        print(f"Running 'npm update {package_name}' in {app_root_dir}")
        if not run_command(["npm", "update", package_name], cwd=app_root_dir):
            raise Exception("npm update failed")
        print(f"Successfully ran 'npm update {package_name}'.")
        return True
    except Exception as e:
        print(f"npm update failed for {package_name}: {e}. Trying npm install with fixed version.")
        # If npm update fails or doesn't update to the desired fixed_version, try npm install
        try:
            install_cmd = ["npm", "install", f"{package_name}@{fixed_version}"]
            print(f"Running '{' '.join(install_cmd)}' in {app_root_dir}")
            if not run_command(install_cmd, cwd=app_root_dir):
                raise Exception("npm install failed")
            print(f"Successfully ran 'npm install {package_name}@{fixed_version}'.")
            return True
        except Exception as e:
            print(f"Failed to fix NPM package '{package_name}' with fixed version '{fixed_version}': {e}")
            return False

def harden_dockerfile(dockerfile_path):
    """
    Applies basic Dockerfile hardening:
    - Ensures a non-root user is used if not already.
    - Adds a WORKDIR if not present.
    """
    print(f"Applying hardening to Dockerfile: {dockerfile_path}")
    try:
        if not os.path.exists(dockerfile_path):
            print(f"Dockerfile '{dockerfile_path}' not found for hardening.")
            return False

        with open(dockerfile_path, 'r') as f:
            lines = f.readlines()

        new_lines = []
        user_set = False
        workdir_set = False
        
        # Check for existing USER and WORKDIR directives
        for line in lines:
            if line.strip().upper().startswith("USER"):
                user_set = True
            if line.strip().upper().startswith("WORKDIR"):
                workdir_set = True
            new_lines.append(line)

        # Add USER if not set to non-root or if 'USER root' is explicitly used.
        updated_user = False
        if not user_set or "USER root" in "".join(lines).upper():
            # Attempt to add a non-root user after the base image and package installations
            # This is a heuristic and might need adjustment based on the Dockerfile structure
            insert_index = -1
            for i, line in enumerate(lines):
                if line.strip().upper().startswith("RUN"):
                    insert_index = i + 1
                elif line.strip().upper().startswith("FROM"):
                    if insert_index == -1: # if no RUN after FROM, insert after FROM
                        insert_index = i + 1

            if insert_index != -1:
                # Add a non-root user. For Node.js, 'node' user often exists.
                # Otherwise, you'd need to add commands to create a user.
                user_add_commands = [
                    "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\\n",
                    "USER appuser\\n"
                ]
                # Check if base image provides a 'node' user by default (common in Node.js images)
                from_line = next((l for l in lines if l.strip().upper().startswith("FROM")), "").lower()
                if "node:" in from_line:
                    user_add_commands = ["USER node\\n"] # Assume 'node' user exists
                
                # If 'USER root' is explicitly used, replace it
                if "USER root" in "".join(lines).upper():
                    print("Found 'USER root', attempting to replace with non-root user.")
                    temp_lines = []
                    for line in lines:
                        if line.strip().upper() == "USER ROOT":
                            temp_lines.extend(user_add_commands)
                        else:
                            temp_lines.append(line)
                    new_lines = temp_lines # Apply changes to new_lines for further processing
                    print("Replaced 'USER root' with non-root user commands.")
                    updated_user = True
                elif not user_set: # Only add if no USER instruction was present initially
                    # Need to convert list of strings to single string for insert
                    new_lines.insert(insert_index, "\\n" + "".join(user_add_commands))
                    print("Added non-root user to Dockerfile.")
                    updated_user = True
            else:
                print("Could not find suitable insertion point for USER instruction.")
        else:
            print("Dockerfile already has a USER instruction (and not 'root'). Skipping user hardening.")
        
        # Add WORKDIR if not set (best practice)
        updated_workdir = False
        if not workdir_set:
            # Try to insert WORKDIR after USER or after FROM if no user was added
            insert_point_found = False
            for i, line in enumerate(new_lines):
                if line.strip().upper().startswith("USER"):
                    new_lines.insert(i + 1, "WORKDIR /app\\n")
                    print("Added WORKDIR /app to Dockerfile after USER.")
                    updated_workdir = True
                    insert_point_found = True
                    break
                elif line.strip().upper().startswith("FROM"):
                    if not insert_point_found: # If WORKDIR wasn't added after USER, add after FROM
                        new_lines.insert(i + 1, "WORKDIR /app\\n")
                        print("Added WORKDIR /app to Dockerfile after FROM.")
                        updated_workdir = True
                        insert_point_found = True
                        break
            if not insert_point_found: # Fallback: add at the very beginning
                new_lines.insert(0, "WORKDIR /app\\n")
                print("Added WORKDIR /app to Dockerfile at start.")
                updated_workdir = True
        else:
            print("Dockerfile already has a WORKDIR instruction. Skipping WORKDIR hardening.")

        if not updated_user and not updated_workdir:
            print("No significant Dockerfile hardening changes needed (USER and WORKDIR are present/handled).")
            return False # No changes were made based on these rules
        
        with open(dockerfile_path, 'w') as f:
            f.writelines(new_lines)
        print(f"Dockerfile '{dockerfile_path}' hardened successfully.")
        return True

    except Exception as e:
        print(f"Error hardening Dockerfile: {e}")
        return False

def main():
    # Expect trivy_report.json, dockerfile_path, and app_root_dir as command line arguments
    if len(sys.argv) < 4:
        print("Usage: python remediate.py <trivy_report.json> <dockerfile_path> <app_root_dir>")
        sys.exit(1)

    report_path = sys.argv[1]
    dockerfile_path = sys.argv[2]
    app_root_dir = sys.argv[3]


    if not os.path.exists(report_path):
        print(f"Trivy report not found at {report_path}. Exiting.")
        sys.exit(1)
    # Allowing Dockerfile to be optional for OS fixes, but warning
    if not os.path.exists(dockerfile_path):
        print(f"Dockerfile not found at {dockerfile_path}. Proceeding but OS fixes may be limited.")
    if not os.path.isdir(app_root_dir):
        print(f"Application root directory not found at {app_root_dir}. Exiting.")
        sys.exit(1)

    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON report: {e}. Report content:\\n{open(report_path).read()}")
        sys.exit(1)

    vulnerabilities_found = 0
    vulnerabilities_fixed = 0
    repo_changed = False # Track if any file in the repo was changed

    for result in report.get("Results", []):
        target = result.get("Target", "")
        vulnerabilities = result.get("Vulnerabilities", [])

        if not vulnerabilities:
            continue

        print(f"\\nProcessing vulnerabilities for target: {target}")

        for vuln in vulnerabilities:
            vulnerabilities_found += 1
            vuln_id = vuln.get("VulnerabilityID", "N/A")
            pkg_name = vuln.get("PkgName", "N/A")
            installed_version = vuln.get("InstalledVersion", "N/A")
            fixed_version = vuln.get("FixedVersion", "")
            severity = vuln.get("Severity", "UNKNOWN")
            data_source = vuln.get("DataSource", {}).get("ID", "N/A").lower()

            if not fixed_version or fixed_version.lower() == "not fixed":
                print(f"  [SKIPPING] {vuln_id} ({pkg_name}): No fix available ({severity}).")
                continue

            print(f"  [ATTEMPTING FIX] {vuln_id} ({pkg_name}) {installed_version} -> {fixed_version} ({severity})")

            fixed_current_vuln = False

            if "npm" in data_source or "node.js" in target.lower() or "package.json" in target.lower():
                print("  [INFO] Attempting NPM fix. This will likely fail in simulation if npm is not installed/in PATH.")
                try:
                    if fix_npm_dependency(pkg_name, fixed_version, app_root_dir):
                        fixed_current_vuln = True
                except Exception as e:
                    print(f"  [ERROR] NPM fix failed due to environment issue: {e}")
            elif "pip" in data_source or "python" in target.lower() or "pipfile.lock" in target.lower() or "requirements.txt" in target.lower():
                print(f"  [TODO] Implement pip fix for {pkg_name}. Requires 'pip install --upgrade {pkg_name}=={fixed_version}' in {app_root_dir}")
            elif "gem" in data_source or "ruby" in target.lower() or "gemfile.lock" in target.lower():
                print(f"  [TODO] Implement gem fix for {pkg_name}. Requires 'bundle update {pkg_name}' or 'bundle install {pkg_name}' in {app_root_dir}")
            elif "go" in data_source or "go.mod" in target.lower():
                print(f"  [TODO] Implement go mod fix for {pkg_name}. Requires 'go get -u {pkg_name}' then 'go mod tidy' in {app_root_dir}")
            elif any(os_distro in data_source for os_distro in ["debian", "alpine", "redhat", "ubuntu", "centos"]) or "os" in target.lower():
                if os.path.exists(dockerfile_path):
                    try:
                        with open(dockerfile_path, 'r') as f:
                            dockerfile_content = f.read()
                        
                        from_match = re.search(r"FROM\\s+(\\S+)", dockerfile_content, re.IGNORECASE)
                        if from_match:
                            current_base_image = from_match.group(1).strip()
                            updated_base_image = None
                            
                            if "alpine" in current_base_image.lower():
                                match = re.search(r"alpine:(\\d+\\.\\d+)", current_base_image, re.IGNORECASE)
                                if match:
                                    major_minor = match.group(1)
                                    parts = [int(p) for p in major_minor.split('.')]
                                    new_minor = parts[1] + 1
                                    updated_base_image = current_base_image.replace(major_minor, f"{parts[0]}.{new_minor}")
                                else:
                                    updated_base_image = current_base_image.split(':')[0] + ":latest"
                            elif "debian" in current_base_image.lower():
                                updated_base_image = current_base_image.split(':')[0] + ":latest"
                            elif "ubuntu" in current_base_image.lower():
                                updated_base_image = current_base_image.split(':')[0] + ":latest"

                            if updated_base_image and update_dockerfile_base_image(dockerfile_path, current_base_image, updated_base_image):
                                fixed_current_vuln = True
                            else:
                                print(f"    Could not automatically update base image for OS package {pkg_name}. Manual intervention may be required.")
                        else:
                            print(f"    Could not identify base image in {dockerfile_path} for OS package {pkg_name}.")
                    except Exception as e:
                        print(f"    Error reading Dockerfile for OS vulnerability: {e}")
                else:
                    print(f"    Dockerfile not provided at {dockerfile_path}. Cannot fix OS vulnerabilities automatically.")
            else:
                print(f"  [SKIPPING] {vuln_id} ({pkg_name}): Remediation for this type (DataSource: '{data_source}', Target: '{target}') not implemented or not applicable for auto-fix.")
            
            if fixed_current_vuln:
                vulnerabilities_fixed += 1
                repo_changed = True

    # Apply general Dockerfile hardening if a Dockerfile path was provided
    if os.path.exists(dockerfile_path):
        if harden_dockerfile(dockerfile_path):
            repo_changed = True

    if vulnerabilities_found == 0:
        print("\\nNo vulnerabilities found in the report.")
        sys.exit(0)
    elif vulnerabilities_fixed == vulnerabilities_found:
        print(f"\\nAll {vulnerabilities_fixed} vulnerabilities found have been fixed!")
        sys.exit(0)
    elif vulnerabilities_fixed > 0:
        print(f"\\nSuccessfully fixed {vulnerabilities_fixed} out of {vulnerabilities_found} vulnerabilities. Review remaining issues.")
        sys.exit(0)
    else:
        print(f"\\nCould not automatically fix any of the {vulnerabilities_found} vulnerabilities.")
        sys.exit(1)

if __name__ == "__main__":
    main()
