import os
import re
import json

# Define the folder containing JSON files
folder_path = 'path/to/your/json/files'

# Common regex patterns to identify secrets
patterns = {
    'API_KEY': re.compile(r'[\w-]{20,}'),
    'PASSWORD': re.compile(r'(?i)(password|pwd|pass|secret|token|key)[\'"\s:]*([^\s\'"]+)'),
    'TOKEN': re.compile(r'(?i)(token)[\'"\s:]*([^\s\'"]+)'),
    'DOMAIN': re.compile(r'@engineering\.digital\.dwp\.gov\.uk')
}

def scan_file(file_path):
    with open(file_path, 'r') as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            print(f"Error decoding JSON in file: {file_path}")
            return []

    findings = []

    def recursive_scan(obj, path=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                recursive_scan(value, f"{path}.{key}" if path else key)
        elif isinstance(obj, list):
            for index, item in enumerate(obj):
                recursive_scan(item, f"{path}[{index}]")
        else:
            for pattern_name, pattern in patterns.items():
                if pattern.search(str(obj)):
                    findings.append((pattern_name, path, obj))

    recursive_scan(data)
    return findings

def main():
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith('.json'):
                file_path = os.path.join(root, file_name)
                findings = scan_file(file_path)
                if findings:
                    print(f"\nFindings in file: {file_path}")
                    for pattern_name, json_path, value in findings:
                        print(f"{pattern_name} found at {json_path}: {value}")

if __name__ == "__main__":
    main()
