import os
import re

# Define patterns to search for
patterns = {
    'AWS Access Key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'AWS Secret Key': re.compile(r'(?i)aws(.{0,20})?[''"][0-9a-zA-Z/+]{40}[''"]'),
    'API Key': re.compile(r'(?i)api(.{0,20})?key(.{0,20})?[0-9a-zA-Z]{16,45}'),
    'Private Key': re.compile(r'-----BEGIN (EC|RSA|DSA|PGP|OPENSSH) PRIVATE KEY-----'),
    'Password': re.compile(r'(?i)password(.{0,20})?[:=]["\']?[0-9a-zA-Z!@#$%^&*()_+={}\[\]:;"\'|\\,.<>/?-]{8,}["\']?'),
    'Credentials': re.compile(r'(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)'),
    'Private Keys': re.compile(r'([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)')
}

# Function to scan files for secrets
def scan_file(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as file:
            content = file.read()
            for key, pattern in patterns.items():
                if pattern.search(content):
                    print(f"[!] Potential {key} found in file: {filepath}")
    except (IsADirectoryError, PermissionError):
        pass

# Function to walk through the file system
def scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            scan_file(filepath)

if __name__ == "__main__":
    target_directory = "/"  # Set the target directory to root for macOS
    scan_directory(target_directory)
