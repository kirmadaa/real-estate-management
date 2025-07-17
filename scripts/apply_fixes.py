# scripts/apply_fixes.py
import json
import sys
import re

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

    if not vulnerabilities:
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
        # original_from_line = dockerfile_lines[from_line_index].strip() # Not needed for comparison after direct replacement
        
        # Check if any vulnerability is directly related to the base image and if a newer patch version exists
        # This is a simplified heuristic. A real-world scenario might involve more sophisticated lookup.
        for vuln in vulnerabilities:
            # Check if target matches current base image (case-insensitive for image name)
            # and vulnerability type is OS-related.
            # Using current_base_image_name in vulnerability target for checking
            if f"{current_base_image_name.lower()}:{current_base_image_tag}" in vuln['Target'].lower() and \
               vuln['Type'] in ['alpine', 'debian', 'centos', 'redhat', 'suse']:
                
                new_base_image = None
                # Attempt to infer a newer patch version of the base image
                # This is highly heuristic and may need custom logic per image type (e.g., alpine:3.18 -> alpine:3.19)
                try:
                    # Simple split for numeric tags (e.g., "3.18.0" -> "3.18.1")
                    parts = current_base_image_tag.split('.')
                    if len(parts) > 1 and parts[-1].isdigit():
                        new_tag_num = int(parts[-1]) + 1
                        new_base_image_tag = ".".join(parts[:-1] + [str(new_tag_num)])
                        new_base_image = f"{current_base_image_name}:{new_base_image_tag}"
                    elif vuln.get('FixedVersion') and current_base_image_name.lower() in vuln['Target'].lower():
                         # If fixed version is provided for the base image itself (e.g., alpine:3.18.5)
                         new_base_image = f"{current_base_image_name}:{vuln['FixedVersion']}"
                except ValueError:
                    pass # Not a simple numeric tag, skip for now.

                # Check if the base image is already the suggested new version to prevent unnecessary changes
                if new_base_image and f"FROM {new_base_image}" not in modified_dockerfile_lines[from_line_index]: # check current modified line
                    print(f"Attempting to upgrade base image from {current_base_image_name}:{current_base_image_tag} to {new_base_image}")
                    # Replace the entire FROM line, ensuring no inline comments
                    modified_dockerfile_lines[from_line_index] = f"FROM {new_base_image}\n"
                    changes_made = True
                    # Exit after finding the first base image upgrade opportunity and applying it
                    break 

    # Strategy 2: Add RUN commands for package upgrades
    os_packages_to_upgrade = {} # {pkg_name: fix_version}
    python_packages_to_upgrade = {} # {pkg_name: fix_version}

    for vuln in vulnerabilities:
        pkg_name = vuln['PkgName']
        fix_version = vuln['FixedVersion']
        
        # Collect OS-level packages
        if vuln['Type'] in ['alpine', 'debian', 'centos', 'redhat'] and pkg_name and fix_version:
            os_packages_to_upgrade[pkg_name] = fix_version
        # Collect Python packages separately
        elif vuln['Type'] == 'python-pkg' and pkg_name and fix_version:
            python_packages_to_upgrade[pkg_name] = fix_version

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
            
            # Find the best insertion point: after FROM or after the last existing RUN
            insert_index = from_line_index + 1 if from_line_index != -1 else 0
            for i, line in enumerate(modified_dockerfile_lines[from_line_index + 1:], start=from_line_index + 1):
                if line.strip().startswith("RUN"):
                    insert_index = i + 1
            
            # Check if this exact RUN command or a similar upgrade command already exists
            if upgrade_command_line.strip() not in [line.strip() for line in modified_dockerfile_lines]:
                # Also check for apt-get update or apk update as standalone, to avoid redundancy
                if not any("apt-get update" in l or "apk update" in l for l in modified_dockerfile_lines[insert_index:]):
                    modified_dockerfile_lines.insert(insert_index, "# Added by apply_fixes.py for OS package upgrades\n")
                    modified_dockerfile_lines.insert(insert_index + 1, upgrade_command_line)
                    changes_made = True

    # Handle Python package upgrades
    if python_packages_to_upgrade:
        print(f"Identified Python packages to upgrade: {python_packages_to_upgrade}")
        pip_commands = [f"pip install --upgrade {pkg}" for pkg in python_packages_to_upgrade.keys()]
        
        if pip_commands:
            pip_upgrade_line = f"RUN {' && '.join(pip_commands)}\n"
            
            # Find the insertion point: ideally after the initial pip install for requirements.txt
            # Or after any existing RUN, but before COPY/ADD for application code
            insert_index = -1
            # Look for WORKDIR or COPY/ADD instructions as a boundary
            for i, line in enumerate(modified_dockerfile_lines):
                if line.strip().startswith(("WORKDIR", "COPY", "ADD")):
                    insert_index = i
                    break
            
            # If no WORKDIR/COPY/ADD, insert after last RUN, or after FROM
            if insert_index == -1:
                insert_index = from_line_index + 1 if from_line_index != -1 else 0
                for i, line in reversed(list(enumerate(modified_dockerfile_lines[:insert_index]))):
                    if line.strip().startswith("RUN"):
                        insert_index = i + 1
                        break
            
            # Check for duplicates of the pip upgrade command
            if pip_upgrade_line.strip() not in [line.strip() for line in modified_dockerfile_lines]:
                modified_dockerfile_lines.insert(insert_index, "# Added by apply_fixes.py for Python packages\n")
                modified_dockerfile_lines.insert(insert_index + 1, pip_upgrade_line)
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
