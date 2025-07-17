import json
import sys
import re
import os
from packaging.version import parse as parse_version

# Define a global log file path for debugging
DEBUG_LOG_FILE = "apply_fixes_debug.log"

def log_debug(message):
    """Writes debug messages to a dedicated log file."""
    with open(DEBUG_LOG_FILE, 'a') as f:
        f.write(f"DEBUG: {message}\n")
    # Also print to stdout, in case it eventually shows up
    print(f"DEBUG: {message}")

def get_base_image_info(dockerfile_lines):
    """Extracts base image name and tag from Dockerfile lines."""
    for line in dockerfile_lines:
        match = re.match(r'FROM\s+([^\s:]+)(?::(\S+))?', line, re.IGNORECASE)
        if match:
            image_name = match.group(1)
            image_tag = match.group(2) if match.group(2) else 'latest'
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
    # Clear the debug log file at the beginning of each run
    if os.path.exists(DEBUG_LOG_FILE):
        os.remove(DEBUG_LOG_FILE)

    try:
        with open(vulnerabilities_json_path, 'r') as f:
            vulnerabilities = json.load(f)
    except FileNotFoundError:
        print(f"No vulnerabilities file found at {vulnerabilities_json_path}. No fixes to apply.")
        if os.path.exists(dockerfile_path + ".fixed"):
            os.remove(dockerfile_path + ".fixed")
        return
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {vulnerabilities_json_path}", file=sys.stderr)
        sys.exit(1)

    vulnerabilities_data = []
    if isinstance(vulnerabilities, dict) and 'Results' in vulnerabilities:
        vulnerabilities_data = vulnerabilities['Results']
    elif isinstance(vulnerabilities, list):
        vulnerabilities_data = vulnerabilities
    else:
        print("Error: Unexpected JSON structure. Expected a dictionary with 'Results' or a list.", file=sys.stderr)
        sys.exit(1)

    if not vulnerabilities_data:
        print("No fixable vulnerabilities identified in the report.")
        if os.path.exists(dockerfile_path + ".fixed"):
            os.remove(dockerfile_path + ".fixed")
        return

    try:
        with open(dockerfile_path, 'r') as f:
            dockerfile_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Dockerfile not found at {dockerfile_path}", file=sys.stderr)
        sys.exit(1)

    modified_dockerfile_lines = list(dockerfile_lines)
    changes_made = False

    current_base_image_name, current_base_image_tag = get_base_image_info(dockerfile_lines)
    from_line_index = find_from_line_index(dockerfile_lines)

    # Strategy 1: Prioritize base image update
    if current_base_image_name and from_line_index != -1:
        for result in vulnerabilities_data:
            if result.get('Target', '').lower().startswith(f"{current_base_image_name.lower()}:{current_base_image_tag}") and \
               result.get('Type') in ['alpine', 'debian', 'centos', 'redhat', 'suse']:

                new_base_image = None
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
    os_packages_to_upgrade = {}
    python_packages_to_upgrade_target_versions = {}

    for result in vulnerabilities_data:
        target_type = result.get('Type')

        if target_type in ['alpine', 'debian', 'centos', 'redhat', 'suse'] and 'Vulnerabilities' in result:
            for vuln in result['Vulnerabilities']:
                pkg_name = vuln.get('PkgName')
                fix_version = vuln.get('FixedVersion')
                if pkg_name and fix_version and vuln.get('InstalledVersion'):
                    try:
                        installed_v = parse_version(vuln['InstalledVersion'])
                        fixed_vs = sorted([parse_version(v.strip()) for v in fix_version.split(',')], reverse=True)
                        for fv in fixed_vs:
                            if fv > installed_v:
                                os_packages_to_upgrade[pkg_name] = str(fv)
                                changes_made = True
                                break
                    except Exception as e:
                        print(f"Warning: Could not parse OS package versions for {pkg_name}: {e}", file=sys.stderr)

        elif target_type == 'python-pkg' and 'Vulnerabilities' in result:
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
        if 'alpine' in current_base_image_name.lower():
            package_manager_cmd = "apk upgrade --no-cache"
        elif 'debian' in current_base_image_name.lower() or 'ubuntu' in current_base_image_name.lower():
            package_manager_cmd = "apt-get update && apt-get upgrade -y --no-install-recommends"
        elif 'centos' in current_base_image_name.lower() or 'fedora' in current_base_image_name.lower() or 'redhat' in current_base_image_name.lower():
            package_manager_cmd = "yum update -y"

        if package_manager_cmd:
            upgrade_command_line = f"RUN {package_manager_cmd}\n"
            insert_index = from_line_index + 1 if from_line_index != -1 else 0
            for i, line in enumerate(modified_dockerfile_lines[from_line_index + 1:], start=from_line_index + 1):
                if line.strip().startswith("RUN"):
                    insert_index = i + 1

            if not any(package_manager_cmd.split(' ')[0] in l and ("upgrade" in l or "update" in l) for l in modified_dockerfile_lines):
                modified_dockerfile_lines.insert(insert_index, "# Added by apply_fixes.py for OS package upgrades\n")
                modified_dockerfile_lines.insert(insert_index + 1, upgrade_command_line)
                changes_made = True

    # Handle Python package upgrades
    if python_packages_to_upgrade_target_versions:
        print(f"Identified Python packages to upgrade: {python_packages_to_upgrade_target_versions}")

        pip_upgrade_parts = []
        for pkg, target_version in python_packages_to_upgrade_target_versions.items():
            pip_upgrade_parts.append(f"{pkg}=={target_version}")

        if pip_upgrade_parts:
            new_pip_upgrade_command = f"RUN pip install --no-cache-dir --upgrade {' '.join(pip_upgrade_parts)}\n"

            inserted_or_modified = False
            found_existing_pip_run_line = False

            log_debug(f"Generated new_pip_upgrade_command: '{new_pip_upgrade_command.strip()}'")

            for i, line in enumerate(modified_dockerfile_lines):
                if re.search(r'RUN\s+(pip|python -m pip)\s+install.*', line, re.IGNORECASE):
                    found_existing_pip_run_line = True
                    log_debug(f"Existing pip install line at index {i}: '{line.strip()}'")

                    if new_pip_upgrade_command.strip() != line.strip():
                        log_debug(f"Found existing line is different, modifying it.")
                        modified_dockerfile_lines[i] = new_pip_upgrade_command
                        inserted_or_modified = True
                        changes_made = True
                        break
                    else:
                        log_debug(f"Existing line is identical to generated, no modification needed.")
                        inserted_or_modified = True
                        break

            if not inserted_or_modified and not found_existing_pip_run_line:
                insert_index = -1
                insert_index = from_line_index + 1 if from_line_index != -1 else 0

                for i, line in enumerate(modified_dockerfile_lines):
                    if line.strip().startswith(("WORKDIR", "COPY", "ADD")):
                        insert_index = i
                        break
                    elif line.strip().startswith("RUN"):
                        insert_index = i + 1

                log_debug(f"No existing pip install line found or modified, inserting new one at index {insert_index}")
                modified_dockerfile_lines.insert(insert_index, "# Added by apply_fixes.py for Python packages\n")
                modified_dockerfile_lines.insert(insert_index + 1, new_pip_upgrade_command)
                changes_made = True

    if changes_made:
        print("Changes applied to Dockerfile.")
        with open(dockerfile_path + ".fixed", 'w') as f:
            f.writelines(modified_dockerfile_lines)
        print(f"Dockerfile successfully updated and written to {dockerfile_path}.fixed.")
    else:
        print("No significant changes applied to Dockerfile (or no fixable vulns).")
        if os.path.exists(dockerfile_path + ".fixed"):
            os.remove(dockerfile_path + ".fixed")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 apply_fixes.py <Dockerfile_path> <vulnerabilities.json_path>", file=sys.stderr)
        sys.exit(1)
    dockerfile_path = sys.argv[1]
    vulnerabilities_json = sys.argv[2]
    apply_fixes(dockerfile_path, vulnerabilities_json)
