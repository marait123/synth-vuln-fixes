\
import json
import os
import sys

# --- Configuration ---
INPUT_FILE = "grouped_sonar_issues_by_file_and_cwe.json"
OUTPUT_FILE = "transformed_sonar_issues.json"
# ---------------------

# --- Mappings ---
# Map SonarQube severity to desired Impact
SEVERITY_TO_IMPACT = {
    "BLOCKER": "HIGH",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "LOW",
}

# Map SonarQube severity to desired Severity
SEVERITY_TO_SEVERITY = {
    "BLOCKER": "ERROR",
    "CRITICAL": "ERROR",
    "MAJOR": "ERROR",
    "MINOR": "WARNING",
    "INFO": "WARNING",
}
# ----------------


def load_sonar_data(input_file):
    """Loads the grouped SonarQube issues from a JSON file."""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"Successfully loaded data from {input_file}")
        return data
    except FileNotFoundError:
        print(f"Error: Input file not found at {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {input_file}: {e}")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file {input_file}: {e}")
        sys.exit(1)


def transform_data(sonar_data):
    """Transforms the SonarQube data into the desired output format."""
    transformed_output = {}
    print("Transforming data...")

    for file_entry in sonar_data:
        original_file_path = file_entry.get("file_name")
        issues = file_entry.get("issues", [])

        if not original_file_path:
            print("Warning: Skipping entry with missing 'file_name'")
            continue

        # Normalize path separators to '/' and split
        # Expecting format like: data/repo_name/commit_hash/files/actual_path.py
        # Or on Windows: data\\repo_name\\commit_hash\\files\\actual_path.py
        normalized_path = original_file_path.replace('\\', '/')
        parts = normalized_path.split('/')

        # Ensure the path has enough parts (data, repo, commit, files, ...)
        if len(parts) < 4 or parts[0] != 'data' or parts[3] != 'files':
            print(
                f"Warning: Skipping file with unexpected path structure: {original_file_path}")
            continue

        repo_name = parts[1]
        commit_hash = parts[2]
        repo_commit_key = f"{repo_name}/{commit_hash}"

        # Reconstruct the desired file path format
        # e.g., repo_name/commit_hash/files/actual_path.py
        output_file_path = f"{repo_name}/{commit_hash}/{'/'.join(parts[3:])}"

        if repo_commit_key not in transformed_output:
            transformed_output[repo_commit_key] = {
                "detected_files_meta_data": []
            }

        for issue in issues:
            sonar_severity = issue.get("severity")
            cwe = issue.get("queried_cwe")  # Already in "CWE-XXX" format

            if not sonar_severity or not cwe:
                print(
                    f"Warning: Skipping issue in {original_file_path} due to missing severity or CWE.")
                continue

            # Map severity to impact and output severity
            impact = SEVERITY_TO_IMPACT.get(
                sonar_severity, "UNKNOWN")  # Default if mapping missing
            output_severity = SEVERITY_TO_SEVERITY.get(
                sonar_severity, "UNKNOWN")  # Default if mapping missing
            likelihood = "LOW"  # Fixed as per example

            meta_data_entry = {
                "file_path": output_file_path,
                "impact": impact,
                "likelihood": likelihood,
                "severity": output_severity,
                "cwes": [cwe]  # Put the CWE in a list
            }
            transformed_output[repo_commit_key]["detected_files_meta_data"].append(
                meta_data_entry)

    print(
        f"Transformation complete. Processed {len(transformed_output)} repo/commit entries.")
    return transformed_output


def save_transformed_data(data, output_file):
    """Saves the transformed data to a JSON file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print(f"Successfully saved transformed data to {output_file}")
    except IOError as e:
        print(f"Error saving data to {output_file}: {e}")


if __name__ == "__main__":
    sonar_issues_data = load_sonar_data(INPUT_FILE)
    if sonar_issues_data:
        transformed_result = transform_data(sonar_issues_data)
        save_transformed_data(transformed_result, OUTPUT_FILE)
