# scripts/apply_fixes.py
import json
import sys
import re

def get_base_image_info(dockerfile_content):
    """Extracts base image name and tag from Dockerfile."""
    match = re.search(r'FROM\s+([^\s:]+)(?::(\S+))?', dockerfile_content, re.IGNORECASE)
    if match:
        image_name = match.group(1)
        image_tag = match.group(2) if match.group(2) else 'latest' # Default to latest if no tag specified
        return image_name, image_tag
    return None, None

def replace_base_image(dockerfile_content, old_image, new_image):
    """Replaces the base image in the Dockerfile."""
    return re.sub(r'FROM\s+' + re.escape(old_image), f'FROM {new_image}', dockerfile_content, flags=re.IGNORECASE)

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

    original_dockerfile_content = "".join(dockerfile_lines)
    modified_dockerfile_content = list(dockerfile_lines) # Create a mutable list of lines

    changes_made = False

    # Strategy 1: Prioritize base image update
    current_base_image_name, current_base_image_tag = get_base_image_info(original_dockerfile_content)
    
    if current_base_image_name:
        # Check if any vulnerability is directly related to the base image and if a newer patch version exists
        # This is a simplified heuristic. A real-world scenario might involve more sophisticated lookup.
        for vuln in vulnerabilities:
            if vuln['Target'] == f"{current_base_image_name}:{current_base_image_tag}" and vuln['Type'] in ['alpine', 'debian', 'centos', 'redhat', 'suse']:
                # Attempt to infer a newer patch version of the base image
                # This is highly heuristic and may need custom logic per image type (e.g., alpine:3.18 -> alpine:3.19)
                try:
                    # Simple split for numeric tags
                    parts = current_base_image_tag.split('.')
                    if len(parts) > 1 and parts[-1].isdigit():
                        new_tag_num = int(parts[-1]) + 1
                        new_base_image_tag = ".".join(parts[:-1] + [str(new_tag_num)])
                        new_base_image = f"{current_base_image_name}:{new_base_image_tag}"

                        # Assuming a new base image can resolve multiple OS-level vulns
                        print(f"Attempting to upgrade base image from {current_base_image_name}:{current_base_image_tag} to {new_base_image}")
                        modified_dockerfile_content = [
                            replace_base_image(line, f"{current_base_image_name}:{current_base_image_tag}", new_base_image) 
                            if f"FROM {current_base_image_name}:{current_base_image_tag}" in line else line
                            for line in modified_dockerfile_content
                        ]
                        changes_made = True
                        # Exit after finding the first base image upgrade opportunity
                        break 
                except ValueError:
                    # Not a simple numeric tag, skip for now.
                    pass
            elif 'alpine' in current_base_image_name.lower() and vuln['Type'] == 'alpine' and vuln['FixedVersion']:
                # Specific logic for Alpine, trying to apply fixed version as new base image tag
                # This assumes FixedVersion can be a new base image tag like "3.18.5"
                new_base_image = f"{current_base_image_name}:{vuln['FixedVersion']}"
                print(f"Attempting to upgrade Alpine base image to {new_base_image}")
                modified_dockerfile_content = [
                    replace_base_image(line, f"{current_base_image_name}:{current_base_image_tag}", new_base_image)
                    if f"FROM {current_base_image_name}:{current_base_image_tag}" in line else line
                    for line in modified_dockerfile_content
                ]
                changes_made = True
                break

    # Strategy 2: Add RUN commands for package upgrades
    # This assumes common package managers. Needs expansion for more.
    packages_to_upgrade = {} # {pkg_name: fix_version}

    for vuln in vulnerabilities:
        pkg_name = vuln['PkgName']
        fix_version = vuln['FixedVersion']
        # Only consider if not already handled by base image upgrade (simple check)
        if not changes_made: # If base image was upgraded, assume OS packages are fixed.
            if vuln['Type'] in ['debian', 'alpine', 'centos', 'redhat'] and pkg_name and fix_version:
                packages_to_upgrade[pkg_name] = fix_version
            elif vuln['Type'] == 'python-pkg' and pkg_name and fix_version:
                packages_to_upgrade[pkg_name] = fix_version # For pip

    if packages_to_upgrade:
        print(f"Identified packages to upgrade: {packages_to_upgrade}")
        
        # Determine the package manager based on the base image
        package_manager_cmd = ""
        if 'alpine' in current_base_image_name.lower():
            package_manager_cmd = "apk upgrade --no-cache"
        elif 'debian' in current_base_image_name.lower() or 'ubuntu' in current_base_image_name.lower():
            package_manager_cmd = "apt-get update && apt-get upgrade -y --no-install-recommends"
        elif 'centos' in current_base_image_name.lower() or 'fedora' in current_base_image_name.lower() or 'redhat' in current_base_image_name.lower():
            package_manager_cmd = "yum update -y" # or dnf
        elif 'python' in current_base_image_name.lower() and any(v['Type'] == 'python-pkg' for v in vulnerabilities):
            # For Python, we might add specific pip commands
            pip_commands = [f"pip install --upgrade {pkg}" for pkg in packages_to_upgrade.keys()]
            if pip_commands:
                # Find the last RUN instruction or just before first COPY/CMD/ENTRYPOINT
                insert_index = -1
                for i, line in reversed(list(enumerate(modified_dockerfile_content))):
                    if line.strip().startswith("RUN"):
                        insert_index = i + 1
                        break
                if insert_index == -1: # If no RUN found, insert after FROM
                    insert_index = 1
                
                # Insert pip upgrade commands
                modified_dockerfile_content.insert(insert_index, f"RUN {' && '.join(pip_commands)}\n")
                changes_made = True


        if package_manager_cmd and not 'python-pkg' in [v['Type'] for v in vulnerabilities]: # Don't mix general OS upgrade with specific pip
            # Add a RUN instruction to upgrade all packages (simplistic, for demo)
            # A more precise method would involve specific package versions.
            upgrade_command = f"RUN {package_manager_cmd}\n"
            
            # Find the last RUN instruction to insert the upgrade command after it
            # Or insert after FROM if no RUN instructions exist
            insert_index = -1
            for i, line in reversed(list(enumerate(modified_dockerfile_content))):
                if line.strip().startswith("RUN"):
                    insert_index = i + 1
                    break
            if insert_index == -1: # If no RUN found, insert after FROM
                insert_index = 1

            # Check if this exact RUN command already exists to prevent duplicates
            if upgrade_command.strip() not in [line.strip() for line in modified_dockerfile_content]:
                modified_dockerfile_content.insert(insert_index, upgrade_command)
                changes_made = True

    if changes_made:
        print("Changes applied to Dockerfile.")
        with open(dockerfile_path, 'w') as f:
            f.writelines(modified_dockerfile_content)
        # Indicate that Dockerfile was modified
        print("Dockerfile successfully updated with fixes.")
        # This will be picked up by the GitHub Actions workflow
        # No need to explicitly create a .fixed file, just overwrite.
    else:
        print("No significant changes applied to Dockerfile (or no fixable vulns).")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 apply_fixes.py <Dockerfile_path> <vulnerabilities.json_path>", file=sys.stderr)
        sys.exit(1)
    dockerfile_path = sys.argv[1]
    vulnerabilities_json = sys.argv[2]
    apply_fixes(dockerfile_path, vulnerabilities_json)
