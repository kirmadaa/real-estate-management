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
        raise
    except FileNotFoundError:
        print(f"Command not found: {cmd[0]}. Please ensure it's installed and in PATH.")
        sys.exit(1)

def update_dockerfile_base_image(dockerfile_path, current_image, fixed_image):
    """Updates the base image in a Dockerfile."""
    print(f"Attempting to update base image in {dockerfile_path} from {current_image} to {fixed_image}")
    try:
        with open(dockerfile_path, 'r') as f:
            lines = f.readlines()

        new_lines = []
        updated = False
        for line in lines:
            if line.strip().startswith("FROM"):
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

def fix_npm_dependency(package_name, fixed_version, package_json_path):
    """
    Fixes a specific NPM package dependency.
    This tries `npm update <pkg>` first, then `npm install <pkg>@<version>`.
    """
    print(f"Attempting to fix NPM package '{package_name}' to version '{fixed_version}' in {package_json_path}")
    
    # Navigate to the directory containing package.json
    project_dir = os.path.dirname(package_json_path)
    if not os.path.exists(os.path.join(project_dir, 'package.json')):
        print(f"Error: package.json not found at {package_json_path}")
        return False

    # Attempt npm update first
    try:
        print(f"Running 'npm update {package_name}' in {project_dir}")
        run_command(["npm", "update", package_name], cwd=project_dir)
        print(f"Successfully ran 'npm update {package_name}'.")
        return True
    except Exception as e:
        print(f"npm update failed for {package_name}: {e}. Trying npm install with fixed version.")
        # If npm update fails or doesn't update to the desired fixed_version, try npm install
        try:
            install_cmd = ["npm", "install", f"{package_name}@{fixed_version}"]
            print(f"Running '{' '.join(install_cmd)}' in {project_dir}")
            run_command(install_cmd, cwd=project_dir)
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

        # Add USER if not set to non-root. This is a simple check.
        # A more advanced check would be if USER root is explicitly set.
        if not user_set:
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
                    "RUN groupadd --system appgroup && useradd --system --gid appgroup appuser\n",
                    "USER appuser\n"
                ]
                # Check if base image provides a 'node' user by default (common in Node.js images)
                from_line = next((l for l in lines if l.strip().upper().startswith("FROM")), "").lower()
                if "node:" in from_line:
                    user_add_commands = ["USER node\n"] # Assume 'node' user exists
                
                # Check if 'USER root' is explicitly used and try to change it
                if "USER root" in "".join(lines):
                    print("Found 'USER root', attempting to replace with non-root user.")
                    new_lines = []
                    for line in lines:
                        if line.strip().upper() == "USER ROOT":
                            new_lines.extend(user_add_commands)
                        else:
                            new_lines.append(line)
                    print("Replaced 'USER root' with non-root user commands.")
                    updated = True
                else:
                    new_lines.insert(insert_index, "\n" + "".join(user_add_commands))
                    print("Added non-root user to Dockerfile.")
                    updated = True
            else:
                print("Could not find suitable insertion point for USER instruction.")
        else:
            print("Dockerfile already has a USER instruction. Skipping user hardening.")
        
        # Add WORKDIR if not set (best practice)
        if not workdir_set:
            if not user_set: # if we just added a user, insert after it
                insert_index = -1
                for i, line in enumerate(new_lines):
                    if line.strip().upper().startswith("USER"):
                        insert_index = i + 1
                        break
                if insert_index != -1:
                    new_lines.insert(insert_index, "WORKDIR /app\n")
                    print("Added WORKDIR /app to Dockerfile after USER.")
                    updated = True
                else: # if no user was added, add after FROM or at the start
                     new_lines.insert(0, "WORKDIR /app\n")
                     print("Added WORKDIR /app to Dockerfile at start.")
                     updated = True
            else: # if user was already set, insert after FROM
                insert_index = -1
                for i, line in enumerate(new_lines):
                    if line.strip().upper().startswith("FROM"):
                        insert_index = i + 1
                        break
                if insert_index != -1:
                    new_lines.insert(insert_index, "WORKDIR /app\n")
                    print("Added WORKDIR /app to Dockerfile after FROM.")
                    updated = True
                else: # Fallback
                     new_lines.insert(0, "WORKDIR /app\n")
                     print("Added WORKDIR /app to Dockerfile at start.")
                     updated = True
        else:
            print("Dockerfile already has a WORKDIR instruction. Skipping WORKDIR hardening.")


        if user_set and workdir_set:
            print("No significant Dockerfile hardening changes needed (USER and WORKDIR are present).")
            return False # No changes were made based on these rules
        
        with open(dockerfile_path, 'w') as f:
            f.writelines(new_lines)
        print(f"Dockerfile '{dockerfile_path}' hardened successfully.")
        return True

    except Exception as e:
        print(f"Error hardening Dockerfile: {e}")
        return False

def main():
    report_path = "trivy-report.json"
    dockerfile_path = "frontend/Dockerfile"
    package_json_path = "frontend/package.json"

    # Ensure npm is installed for Node.js dependency fixes
    try:
        run_command(["npm", "--version"], check_result=True, capture_output=True)
    except Exception:
        print("npm not found. Please ensure Node.js and npm are installed in the environment.")
        sys.exit(1)

    if not os.path.exists(report_path):
        print(f"Trivy report not found at {report_path}. Exiting.")
        sys.exit(1)

    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON report: {e}. Report content:\n{open(report_path).read()}")
        sys.exit(1)

    vulnerabilities_found = 0
    vulnerabilities_fixed = 0
    dockerfile_changed = False
    npm_dependencies_changed = False

    for result in report:
        target = result.get("Target", "")
        vulnerabilities = result.get("Vulnerabilities", [])

        if not vulnerabilities:
            continue

        print(f"\nProcessing vulnerabilities for target: {target}")

        for vuln in vulnerabilities:
            vulnerabilities_found += 1
            vuln_id = vuln.get("VulnerabilityID", "N/A")
            pkg_name = vuln.get("PkgName", "N/A")
            installed_version = vuln.get("InstalledVersion", "N/A")
            fixed_version = vuln.get("FixedVersion", "")
            severity = vuln.get("Severity", "UNKNOWN")
            data_source = vuln.get("DataSource", "N/A")

            if not fixed_version or fixed_version.lower() == "not fixed":
                print(f"  [SKIPPING] {vuln_id} ({pkg_name}): No fix available ({severity}).")
                continue

            print(f"  [ATTEMPTING FIX] {vuln_id} ({pkg_name}) {installed_version} -> {fixed_version} ({severity})")

            # Prioritize based on target type
            if "package.json" in target and data_source == "npm":
                if fix_npm_dependency(pkg_name, fixed_version, package_json_path):
                    vulnerabilities_fixed += 1
                    npm_dependencies_changed = True
                else:
                    print(f"    Failed to fix NPM dependency {pkg_name}.")
            elif "dockerfile" in target.lower() or "os" in target.lower() or data_source in ["debian", "alpine", "redhat", "ubuntu"]:
                # This logic tries to infer the base image from the Dockerfile
                # and if the vulnerability is reported against the OS layer.
                # A more robust solution might involve parsing SBOM for base image details.
                if "fixed-version" in vuln and pkg_name.lower() in ["glibc", "libc", "openssl", "curl", "bash"]: # Common OS packages
                     # This indicates a base OS component. The best fix is often to update the base image.
                     # We need to extract the current base image from Dockerfile to propose an update.
                    try:
                        with open(dockerfile_path, 'r') as f:
                            dockerfile_content = f.read()
                        
                        from_match = re.search(r"FROM\s+(\S+)", dockerfile_content, re.IGNORECASE)
                        if from_match:
                            current_base_image = from_match.group(1).strip()
                            # Simplistic attempt to derive a "fixed" base image tag
                            # This needs to be smarter, e.g., using a mapping of base image updates
                            # For demonstration, we'll try to increment the minor version or append a "new" tag
                            # In a real scenario, this would consult a database of secure base images
                            
                            # Simple heuristic: try to replace the tag with 'latest' for the given image name
                            # E.g., 'node:16-alpine' -> 'node:latest-alpine' (if such exists and is secure)
                            # Or, try to get a newer patch version, e.g., 'alpine:3.16' -> 'alpine:3.17' or 'alpine:3.16.1'
                            
                            # This is the most challenging part for generic automation.
                            # For simplicity, if fixed_version is available for an OS package,
                            # we'll try to update the base image to a presumed 'newer' version by trying to
                            # replace the current tag with something that includes the fixed version, if applicable,
                            # or just indicating a general "upgrade base image" action.
                            
                            # A pragmatic approach is to recommend updating the base image if critical OS vulns found.
                            # We'll hardcode a simple logic for common base images.
                            
                            updated_image_name = None
                            if "alpine" in current_base_image.lower():
                                # Extract current Alpine version, e.g., 3.16, and try to go to 3.17
                                match = re.search(r"alpine:(\d+\.\d+)", current_base_image, re.IGNORECASE)
                                if match:
                                    major_minor = match.group(1)
                                    parts = [int(p) for p in major_minor.split('.')]
                                    new_minor = parts[1] + 1
                                    updated_image_name = current_base_image.replace(major_minor, f"{parts[0]}.{new_minor}")
                                else: # Fallback to latest
                                    updated_image_name = current_base_image.split(':')[0] + ":latest"
                            elif "debian" in current_base_image.lower():
                                # Similar logic for Debian, e.g., 'debian:bullseye-slim' -> 'debian:bookworm-slim'
                                # Or 'debian:11-slim' -> 'debian:12-slim'
                                # This requires mapping distro versions, which is complex.
                                # For simplicity, try to append "-slim-stable" or just "latest"
                                updated_image_name = current_base_image.split(':')[0] + ":latest"
                            elif "ubuntu" in current_base_image.lower():
                                updated_image_name = current_base_image.split(':')[0] + ":latest"
                            
                            if updated_image_name and update_dockerfile_base_image(dockerfile_path, current_base_image, updated_image_name):
                                vulnerabilities_fixed += 1
                                dockerfile_changed = True
                            else:
                                print(f"    Could not automatically update base image for {pkg_name}. Manual intervention may be required.")
                        else:
                            print(f"    Could not identify base image in {dockerfile_path} for OS package {pkg_name}.")
                    except Exception as e:
                        print(f"    Error reading Dockerfile for OS vulnerability: {e}")
            else:
                print(f"  [SKIPPING] {vuln_id} ({pkg_name}): Remediation for this type ({target}, {data_source}) not implemented or not applicable for auto-fix.")

    # Apply general Dockerfile hardening if not already done
    if harden_dockerfile(dockerfile_path):
        dockerfile_changed = True

    if vulnerabilities_found == 0:
        print("\nNo vulnerabilities found in the report.")
        sys.exit(0)
    elif vulnerabilities_fixed == vulnerabilities_found:
        print(f"\nAll {vulnerabilities_fixed} vulnerabilities found have been fixed!")
        sys.exit(0) # Indicate complete success
    elif vulnerabilities_fixed > 0:
        print(f"\nSuccessfully fixed {vulnerabilities_fixed} out of {vulnerabilities_found} vulnerabilities.")
        sys.exit(0) # Indicate partial success, will trigger rebuild/rescan
    else:
        print(f"\nCould not automatically fix any of the {vulnerabilities_found} vulnerabilities.")
        sys.exit(1) # Indicate failure, no fixes applied

if __name__ == "__main__":
    main()
