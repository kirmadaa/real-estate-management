import json
import sys
import re
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
            if result.get('Target').lower().startswith(f"{current_base_image_name.lower()}:{current_base_image_tag}") and \
               result.get('Type') in ['alpine', 'debian', 'centos', 'redhat', 'suse']:
                
                # Check for vulnerabilities directly impacting the OS, and if a fixed version is suggested for the base image
                new_base_image = None
                
                # A more robust approach would involve checking a trusted source for latest secure base images,
                # but for this script, we'll look for a FixedVersion directly in the vuln report for the OS.
                # However, Trivy usually reports OS package vulns, not base image fixed versions directly.
                # This part remains a heuristic as a real-world scenario might need external lookup.
                for vuln in result.get('Vulnerabilities', []):
                    if vuln.get('PkgName', '').lower() == current_base_image_name.lower() and vuln.get('FixedVersion'):
                        new_base_image = f"{current_base_image_name}:{vuln['FixedVersion']}"
                        break
                
                if new_base_image and f"FROM {new_base_image}\n" not in [line.strip() + '\n' for line in modified_dockerfile_lines]:
                    print(f"Attempting to upgrade base image from {current_base_image_name}:{current_base_image_tag} to {new_base_image}")
                    modified_dockerfile_lines[from_line_index] = f"FROM {new_base_image}\n"
                    changes_made = True
                    break

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
                if pkg_name and fix_version:
                    os_packages_to_upgrade[pkg_name] = fix_version
        
        elif target_type == 'python-pkg' and 'Vulnerabilities' in result:
            # Collect Python packages separately
            for vuln in result['Vulnerabilities']:
                pkg_name = vuln.get('PkgName')
                fixed_version_str = vuln.get('FixedVersion')
                installed_version_str = vuln.get('InstalledVersion')

                if pkg_name and fixed_version_str and installed_version_str:
                    try:
                        installed_version = parse_version(installed_version_str)
                        # FixedVersion can be a comma-separated list like "2.3.2, 2.2.5"
                        fixed_versions = sorted([parse_version(v.strip()) for v in fixed_version_str.split(',')], reverse=True)
                        
                        eligible_fixed_version = None
                        for fv in fixed_versions:
                            if fv > installed_version:
                                eligible_fixed_version = fv
                                break # Take the highest eligible fixed version
                        
                        if eligible_fixed_version:
                            # Keep track of the highest required fixed version for each package
                            if pkg_name not in python_packages_to_upgrade_target_versions or \
                               parse_version(python_packages_to_upgrade_target_versions[pkg_name]) < eligible_fixed_version:
                                python_packages_to_upgrade_target_versions[pkg_name] = str(eligible_fixed_version)
                                changes_made = True

                    except Exception as e:
                        print(f"Warning: Could not parse versions for {pkg_name}: {e}", file=sys.stderr)
                        continue

    # Handle general OS package upgrades
    if os_packages_to_upgrade:
        print(f"Identified OS packages to upgrade: {os_packages_to_upgrade}")
        
        package_manager_cmd = ""
        if 'alpine' in current_base_image_name.lower():
            package_manager_cmd = "apk upgrade --no-cache"
        elif 'debian' in current_base_image_name.lower() or 'ubuntu' in current_base_image_name.lower():
            package_manager_cmd = "apt-get update && apt-get upgrade -y --no-install-recommends"
        elif 'centos' in current_base_image_name.lower() or 'fedora' in current_base_image_name.lower() or 'redhat' in current_base_image_name.lower():
            package_manager_cmd = "yum update -y" # or dnf
        
        if package_manager_cmd:
            upgrade_command_line = f"RUN {package_manager_cmd}\n"
            
            insert_index = from_line_index + 1 if from_line_index != -1 else 0
            for i, line in enumerate(modified_dockerfile_lines[from_line_index + 1:], start=from_line_index + 1):
                if line.strip().startswith("RUN"):
                    insert_index = i + 1
            
            # Check if a similar upgrade command already exists to avoid redundant inserts
            if not any(package_manager_cmd in l for l in modified_dockerfile_lines):
                modified_dockerfile_lines.insert(insert_index, "# Added by apply_fixes.py for OS package upgrades\n")
                modified_dockerfile_lines.insert(insert_index + 1, upgrade_command_line)
                changes_made = True

    # Handle Python package upgrades
    if python_packages_to_upgrade_target_versions:
        print(f"Identified Python packages to upgrade: {python_packages_to_upgrade_target_versions}")
        
        pip_upgrade_parts = []
        for pkg, target_version in python_packages_to_upgrade_target_versions.items():
            pip_upgrade_parts.append(f"{pkg}=={target_version}") # Pin to specific fixed version

        if pip_upgrade_parts:
            new_pip_upgrade_command = f"RUN pip install --no-cache-dir --upgrade {' '.join(pip_upgrade_parts)}\n"
            
            inserted_or_modified = False
            # Look for existing pip install lines to modify
            for i, line in enumerate(modified_dockerfile_lines):
                # This regex attempts to find RUN pip install commands that might already include these packages
                if re.search(r'RUN\s+pip\s+install.*', line, re.IGNORECASE):
                    # For simplicity, we'll replace the first found relevant pip install line
                    # with our new, comprehensive one, if it's different.
                    # A more advanced script would parse the existing line and merge.
                    if new_pip_upgrade_command.strip() not in line.strip():
                        print(f"Modifying existing pip install line at index {i}")
                        modified_dockerfile_lines[i] = new_pip_upgrade_command
                        inserted_or_modified = True
                        changes_made = True
                        break # Only modify the first relevant line found

            if not inserted_or_modified:
                # If no existing pip install line was found to modify, insert a new one
                # Find the insertion point: ideally after the initial pip install for requirements.txt
                # Or after any existing RUN, but before COPY/ADD for application code
                insert_index = -1
                for i, line in enumerate(modified_dockerfile_lines):
                    if line.strip().startswith(("WORKDIR", "COPY", "ADD")):
                        insert_index = i
                        break
                
                if insert_index == -1: # If no WORKDIR/COPY/ADD, insert after last RUN, or after FROM
                    insert_index = from_line_index + 1 if from_line_index != -1 else 0
                    for i, line in reversed(list(enumerate(modified_dockerfile_lines[:insert_index]))):
                        if line.strip().startswith("RUN"):
                            insert_index = i + 1
                            break
                
                print(f"Inserting new pip install line at index {insert_index}")
                modified_dockerfile_lines.insert(insert_index, "# Added by apply_fixes.py for Python packages\n")
                modified_dockerfile_lines.insert(insert_index + 1, new_pip_upgrade_command)
                changes_made = True

    if changes_made:
        print("Changes applied to Dockerfile.")
        with open(dockerfile_path, 'w') as f:
            f.writelines(modified_dockerfile_lines)
        print("Dockerfile successfully updated with fixes.")
    else:
        print("No significant changes applied to Dockerfile (or no fixable vulns).")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 apply_fixes.py <Dockerfile_path> <vulnerabilities.json_path>", file=sys.stderr)
        sys.exit(1)
    dockerfile_path = sys.argv[1]
    vulnerabilities_json = sys.argv[2]
    apply_fixes(dockerfile_path, vulnerabilities_json)
