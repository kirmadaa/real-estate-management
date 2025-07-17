import json
import sys
import re
import os # Import os for file operations
from packaging.version import parse as parse_version

def get_base_image_info(dockerfile_lines):
    """Extracts base image name and tag from Dockerfile lines."""
    for line in dockerfile_lines:
        match = re.match(r'FROM\s+([^\s:]+)(?::(\S+))?', line, re.IGNORECASE)
        if match:
            image_name = match.group(1)
            image_tag = match.group(2) if match.group(2) else 'latest' # Default to latest if no tag specified
            return image_name, image_tag
    return None, None

def find_from_line_index(dockerfile_lines):
    """Finds the index of the FROM instruction in Dockerfile lines."""
    for i, line in enumerate(dockerfile_lines):
        if re.match(r'FROM\s+', line, re.IGNORECASE):
            return i
    return -1

def apply_fixes(dockerfile_path, vulnerabilities_json_path):
    """
    Applies fixes to the Dockerfile based on identified vulnerabilities.
    Prioritizes base image updates, then package updates.
    """
    try:
        with open(vulnerabilities_json_path, 'r') as f:
            vulnerabilities = json.load(f)
    except FileNotFoundError:
        print(f"No vulnerabilities file found at {vulnerabilities_json_path}. No fixes to apply.")
        return
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {vulnerabilities_json_path}", file=sys.stderr)
        sys.exit(1)

    if not vulnerabilities or not vulnerabilities.get('Results'):
        print("No fixable vulnerabilities identified in the report.")
        # Ensure Dockerfile.fixed is not created if no fixable vulns
        if os.path.exists(dockerfile_path + ".fixed"):
            os.remove(dockerfile_path + ".fixed")
        return

    try:
        with open(dockerfile_path, 'r') as f:
            dockerfile_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Dockerfile not found at {dockerfile_path}", file=sys.stderr)
        sys.exit(1)

    # Make a copy to modify
    modified_dockerfile_lines = list(dockerfile_lines)
    changes_made = False

    # Strategy 1: Prioritize base image update
    current_base_image_name, current_base_image_tag = get_base_image_info(dockerfile_lines)
    from_line_index = find_from_line_index(dockerfile_lines)

    if current_base_image_name and from_line_index != -1:
        for result in vulnerabilities.get('Results', []):
            # Check if the target directly matches the base image and is an OS type vulnerability
            # Trivy usually lists OS vulnerabilities under `Target` that starts with image name + tag
            # e.g., "alpine:3.18.12 (alpine 3.18.12)" or "go-module (github.com/go-git/go-git/v5)"
            # We are interested in cases where the Target is the base OS itself.
            # This is a heuristic and might need fine-tuning based on Trivy's specific output for base image vulns.
            if result.get('Target', '').lower().startswith(f"{current_base_image_name.lower()}:{current_base_image_tag}") and \
               result.get('Type') in ['alpine', 'debian', 'centos', 'redhat', 'suse']:
                
                new_base_image = None
                # Iterate through vulnerabilities in this result set
                for vuln in result.get('Vulnerabilities', []):
                    # If there's a fixed version specifically for the 'base image' package or a core OS package
                    # that represents an OS upgrade. This is highly dependent on how Trivy reports this.
                    if vuln.get('PkgName', '').lower() == current_base_image_name.lower() and vuln.get('FixedVersion'):
                        # Simplistic: use the fixed version if it's explicitly for the base image name.
                        new_base_image = f"{current_base_image_name}:{vuln['FixedVersion']}"
                        break
                    # More robust check: if any OS package in the current base image context has a fixed version
                    # and the base image itself is EOSL, consider upgrading the base image to a newer patch/minor.
                    # This still requires a heuristic or external data source.
                    # For now, stick to direct fixed version if available for the image name.

                # Check if the generated new_base_image line is not already present
                if new_base_image and f"FROM {new_base_image}\n" not in [line.strip() + '\n' for line in modified_dockerfile_lines]:
                    print(f"Attempting to upgrade base image from {current_base_image_name}:{current_base_image_tag} to {new_base_image}")
                    modified_dockerfile_lines[from_line_index] = f"FROM {new_base_image}\n"
                    changes_made = True
                    break # Apply only one base image upgrade, then proceed

    # Strategy 2: Add RUN commands for package upgrades
    os_packages_to_upgrade = {} # {pkg_name: fix_version}
    python_packages_to_upgrade_target_versions = {} # {pkg_name: highest_fixed_version_str}

    for result in vulnerabilities.get('Results', []):
        target_type = result.get('Type')
        
        if target_type in ['alpine', 'debian', 'centos', 'redhat', 'suse'] and 'Vulnerabilities' in result:
            # Collect OS-level packages
            for vuln in result['Vulnerabilities']:
                pkg_name = vuln.get('PkgName')
                fix_version = vuln.get('FixedVersion')
                if pkg_name and fix_version and vuln.get('InstalledVersion'):
                    try:
                        installed_v = parse_version(vuln['InstalledVersion'])
                        fixed_vs = sorted([parse_version(v.strip()) for v in fix_version.split(',')], reverse=True)
                        for fv in fixed_vs:
                            if fv > installed_v:
                                os_packages_to_upgrade[pkg_name] = str(fv) # Store the highest required fixed version
                                changes_made = True
                                break
                    except Exception as e:
                        print(f"Warning: Could not parse OS package versions for {pkg_name}: {e}", file=sys.stderr)


        elif target_type == 'python-pkg' and 'Vulnerabilities' in result:
            # Collect Python packages
            for vuln in result['Vulnerabilities']:
                pkg_name = vuln.get('PkgName')
                fixed_version_str = vuln.get('FixedVersion')
                installed_version_str = vuln.get('InstalledVersion')

                if pkg_name and fixed_version_str and installed_version_str:
                    try:
                        installed_version = parse_version(installed_version_str)
                        fixed_versions = sorted([parse_version(v.strip()) for v in fixed_version_str.split(',')], reverse=True)
                        
                        eligible_fixed_version = None
                        for fv in fixed_versions:
                            if fv > installed_version:
                                eligible_fixed_version = fv
                                break
                        
                        if eligible_fixed_version:
                            if pkg_name not in python_packages_to_upgrade_target_versions or \
                               parse_version(python_packages_to_upgrade_target_versions[pkg_name]) < eligible_fixed_version:
                                python_packages_to_upgrade_target_versions[pkg_name] = str(eligible_fixed_version)
                                changes_made = True

                    except Exception as e:
                        print(f"Warning: Could not parse Python package versions for {pkg_name}: {e}", file=sys.stderr)
                        continue

    # Handle general OS package upgrades
    if os_packages_to_upgrade:
        print(f"Identified OS packages to upgrade: {os_packages_to_upgrade}")
        
        package_manager_cmd = ""
        # Determine package manager based on base image
        if 'alpine' in current_base_image_name.lower():
            package_manager_cmd = "apk upgrade --no-cache"
        elif 'debian' in current_base_image_name.lower() or 'ubuntu' in current_base_image_name.lower():
            package_manager_cmd = "apt-get update && apt-get upgrade -y --no-install-recommends"
        elif 'centos' in current_base_image_name.lower() or 'fedora' in current_base_image_name.lower() or 'redhat' in current_base_image_name.lower():
            package_manager_cmd = "yum update -y" # or dnf
        
        if package_manager_cmd:
            upgrade_command_line = f"RUN {package_manager_cmd}\n"
            
            # Find insertion point: after FROM or after the last existing RUN
            insert_index = from_line_index + 1 if from_line_index != -1 else 0
            for i, line in enumerate(modified_dockerfile_lines[from_line_index + 1:], start=from_line_index + 1):
                if line.strip().startswith("RUN"):
                    insert_index = i + 1
            
            # Check if a similar upgrade command already exists to avoid redundancy
            # This is a heuristic; a more advanced check would parse and compare specific package upgrades
            if not any(package_manager_cmd.split(' ')[0] in l and ("upgrade" in l or "update" in l) for l in modified_dockerfile_lines):
                modified_dockerfile_lines.insert(insert_index, "# Added by apply_fixes.py for OS package upgrades\n")
                modified_dockerfile_lines.insert(insert_index + 1, upgrade_command_line)
                changes_made = True

    # Handle Python package upgrades
    if python_packages_to_upgrade_target_versions:
        print(f"Identified Python packages to upgrade: {python_packages_to_upgrade_target_versions}")
        
        pip_upgrade_parts = []
        for pkg, target_version in python_packages_to_upgrade_target_versions.items():
            # Pin to specific fixed version to ensure the correct version is installed
            pip_upgrade_parts.append(f"{pkg}=={target_version}")

        if pip_upgrade_parts:
            # Use --no-cache-dir to prevent pip from caching wheels inside the image
            new_pip_upgrade_command = f"RUN pip install --no-cache-dir --upgrade {' '.join(pip_upgrade_parts)}\n"
            
            inserted_or_modified = False
            # Attempt to find and modify an existing RUN pip install line
            for i, line in enumerate(modified_dockerfile_lines):
                if re.search(r'RUN\s+(pip|python -m pip)\s+install.*', line, re.IGNORECASE):
                    # This is a simplified approach: we'll replace the first matching pip install line.
                    # A more robust solution would parse the existing line and intelligently merge the upgrades,
                    # especially if `requirements.txt` is used.
                    if new_pip_upgrade_command.strip() not in line.strip(): # Avoid modifying if already identical
                        print(f"Modifying existing pip install line at index {i}")
                        modified_dockerfile_lines[i] = new_pip_upgrade_command
                        inserted_or_modified = True
                        changes_made = True
                        break # Only modify the first relevant line found

            if not inserted_or_modified:
                # If no existing pip install line was found to modify, insert a new one
                insert_index = -1
                # Find the insertion point: ideally after `FROM` and system-level `RUN` commands,
                # but before `COPY` or `ADD` instructions that bring in application code.
                # Also try to insert after the last existing `RUN` command.
                
                # Default insert after FROM
                insert_index = from_line_index + 1 if from_line_index != -1 else 0

                # Try to find a suitable place after other RUNs but before COPY/ADD/WORKDIR
                for i, line in enumerate(modified_dockerfile_lines):
                    if line.strip().startswith(("WORKDIR", "COPY", "ADD")):
                        insert_index = i # Insert right before these
                        break
                    elif line.strip().startswith("RUN"):
                        insert_index = i + 1 # Keep moving past RUN commands

                print(f"Inserting new pip install line at index {insert_index}")
                modified_dockerfile_lines.insert(insert_index, "# Added by apply_fixes.py for Python packages\n")
                modified_dockerfile_lines.insert(insert_index + 1, new_pip_upgrade_command)
                changes_made = True

    if changes_made:
        print("Changes applied to Dockerfile.")
        # Write to a temporary file, as the shell script expects Dockerfile.fixed
        with open(dockerfile_path + ".fixed", 'w') as f:
            f.writelines(modified_dockerfile_lines)
        print(f"Dockerfile successfully updated and written to {dockerfile_path}.fixed.")
    else:
        print("No significant changes applied to Dockerfile (or no fixable vulns).")
        # Ensure Dockerfile.fixed is NOT created if no changes were made.
        # This aligns with the shell script's `if [ -f "Dockerfile.fixed" ]` check.
        if os.path.exists(dockerfile_path + ".fixed"):
            os.remove(dockerfile_path + ".fixed")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 apply_fixes.py <Dockerfile_path> <vulnerabilities.json_path>", file=sys.stderr)
        sys.exit(1)
    dockerfile_path = sys.argv[1]
    vulnerabilities_json = sys.argv[2]
    apply_fixes(dockerfile_path, vulnerabilities_json)
