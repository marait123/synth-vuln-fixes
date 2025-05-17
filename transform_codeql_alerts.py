\
import csv
import json
import os
import sys
import re

# --- Configuration ---
# Default input CSV from fetch_github_alerts.py
INPUT_FILE = "codeql_security_alerts.csv"
OUTPUT_FILE = "codeql_transformed_github_alerts.json"
# ---------------------\

# --- Mappings ---
# Map GitHub alert severity (rule_severity) to desired Impact
# GitHub severities: critical, high, medium, low, warning, note, error (error is less common for rule_severity)
# Adjust mapping based on desired interpretation
SEVERITY_TO_IMPACT = {
    "critical": "HIGH",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "warning": "LOW",  # Grouping warning with low for impact
    "note": "LOW",    # Grouping note with low for impact
    "error": "MEDIUM",  # Assuming error severity implies medium impact
}

# Map GitHub alert severity to desired Severity
SEVERITY_TO_SEVERITY = {
    "critical": "ERROR",
    "high": "ERROR",
    "medium": "ERROR",
    "low": "WARNING",
    "warning": "WARNING",
    "note": "WARNING",
    "error": "ERROR",
}
# ----------------


def load_github_alerts_csv(input_file):
    """Loads the GitHub alerts from a CSV file."""
    alerts = []
    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            alerts = list(reader)
        print(f"Successfully loaded {len(alerts)} alerts from {input_file}")
        return alerts
    except FileNotFoundError:
        print(f"Error: Input file not found at {input_file}")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file {input_file}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while reading {input_file}: {e}")
        sys.exit(1)


def extract_cwe(tags_string):
    """Extracts CWE identifiers(e.g., CWE-123) from the rule_tags string."""
    if not tags_string:
        return []
    # Regex to find CWE tags like 'external/cwe/cwe-123' or just 'cwe-123'
    # Makes the 'external/cwe/' part optional and captures the 'CWE-XXX' part
    cwe_matches = re.findall(
        r'(?:external/cwe/)?(cwe-\d+)', tags_string, re.IGNORECASE)
    # Return uppercase CWEs
    return [cwe.upper() for cwe in cwe_matches]


def transform_github_data(alerts_data):
    """Transforms the GitHub alerts data into the desired output format."""
    transformed_output = {}
    print("Transforming GitHub alerts data...")
    processed_alerts = 0
    skipped_alerts_path = 0
    skipped_alerts_cwe = 0

    for alert in alerts_data:
        original_file_path = alert.get("most_recent_instance_location_path")
        rule_severity = alert.get("rule_severity")  # GitHub severity
        rule_tags = alert.get("rule_tags")

        if not original_file_path:
            # print("Warning: Skipping alert with missing 'most_recent_instance_location_path'")
            skipped_alerts_path += 1
            continue

        # Normalize path separators to '/' and split
        # Expecting format like: data/repo_name/commit_hash/files/actual_path.py
        normalized_path = original_file_path.replace('\\\\', '/')
        parts = normalized_path.split('/')

        # Ensure the path has enough parts (data, repo, commit, files, ...)
        if len(parts) < 4 or parts[0] != 'data' or parts[3] != 'files':
            # print(f"Warning: Skipping alert with unexpected path structure: {original_file_path}")
            skipped_alerts_path += 1
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

        # Extract CWEs
        cwes = extract_cwe(rule_tags)
        if not cwes:
            # print(f"Warning: No CWE found in tags '{rule_tags}' for alert in {original_file_path}. Skipping this specific alert instance.")
            skipped_alerts_cwe += 1
            # Decide if you want to skip the alert entirely or add it with empty CWE list
            continue  # Skip if no CWE is found, as the target format requires it

        # Map severity to impact and output severity
        # Use lower() for case-insensitive matching
        github_severity_lower = rule_severity.lower(
        ) if rule_severity else "note"  # Default to 'note' if missing
        impact = SEVERITY_TO_IMPACT.get(
            github_severity_lower, "LOW")  # Default if mapping missing
        output_severity = SEVERITY_TO_SEVERITY.get(
            github_severity_lower, "WARNING")  # Default if mapping missing
        likelihood = "LOW"  # Fixed as per example

        meta_data_entry = {
            "file_path": output_file_path,
            "impact": impact,
            "likelihood": likelihood,
            "severity": output_severity,
            "cwes": cwes  # Use the extracted list of CWEs
        }
        transformed_output[repo_commit_key]["detected_files_meta_data"].append(
            meta_data_entry)
        processed_alerts += 1

    print(f"Transformation complete.")
    print(
        f"  Processed {processed_alerts} alert instances into {len(transformed_output)} repo/commit entries.")
    if skipped_alerts_path > 0:
        print(
            f"  Skipped {skipped_alerts_path} alerts due to missing or unexpected file paths.")
    if skipped_alerts_cwe > 0:
        print(
            f"  Skipped {skipped_alerts_cwe} alert instances due to missing CWE tags.")
    return transformed_output


def save_transformed_data(data, output_file):
    """Saves the transformed data to a JSON file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print(f"Successfully saved transformed data to {output_file}")
    except IOError as e:
        print(f"Error saving data to {output_file}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while saving {output_file}: {e}")


if __name__ == "__main__":
    github_alerts = load_github_alerts_csv(INPUT_FILE)
    if github_alerts:
        transformed_result = transform_github_data(github_alerts)
        if transformed_result:
            save_transformed_data(transformed_result, OUTPUT_FILE)
        else:
            print("Transformation resulted in empty data. No output file saved.")
    else:
        print("No alerts loaded or an error occurred during loading.")
