import requests
import json
import math
import time  # Import time for potential delays

# --- Configuration ---
SONAR_URL = "http://localhost:9000"
# Replace with your actual token if different
SONAR_TOKEN = "sqa_a202aaf2844423f4dd1e63a7a0c2493eb8091ac3"
PROJECT_KEY = "synth-vuln-fixes"
PAGE_SIZE = 500  # Max allowed by SonarQube API
OUTPUT_FILE = "all_sonar_issues_by_cwe.json"  # Changed output filename

# List of CWE IDs to query (extracted from your list)
TARGET_CWES = [
    327, 295, 326, 377, 379, 780, 259, 297, 611, 798, 827
]
# ---------------------


def fetch_sonar_issues_by_cwe(cwe_list):
    """Fetches all issues matching the specified CWE list for the project."""
    all_found_issues = []
    total_issues_overall = 0

    print(
        f"Fetching issues for project '{PROJECT_KEY}' from {SONAR_URL} for specific CWEs...")

    for target_cwe in cwe_list:
        print(f"\n--- Querying for CWE-{target_cwe} ---")
        current_page = 1
        total_issues_for_cwe = -1  # Reset for each CWE

        while True:
            api_endpoint = f"{SONAR_URL}/api/issues/search"
            params = {
                "componentKeys": PROJECT_KEY,
                "cwe": str(target_cwe),  # Add the CWE filter
                "ps": PAGE_SIZE,
                "p": current_page
                # Removed 'types' filter to ensure we get all severities/types for the CWE
            }
            # Use token for authentication (as username, empty password)
            auth = (SONAR_TOKEN, '')

            try:
                # Add a small delay to avoid overwhelming the server
                # time.sleep(0.1)
                response = requests.get(
                    api_endpoint, params=params, auth=auth, timeout=90)  # Increased timeout
                response.raise_for_status()

                data = response.json()

                if total_issues_for_cwe == -1:  # First request for this CWE
                    total_issues_for_cwe = data.get('total', 0)
                    if total_issues_for_cwe == 0:
                        print(f"No issues found for CWE-{target_cwe}.")
                        break  # No need to paginate if no issues found
                    total_pages = math.ceil(total_issues_for_cwe / PAGE_SIZE)
                    print(
                        f"Found {total_issues_for_cwe} issues for CWE-{target_cwe} across {total_pages} pages.")

                issues_on_page = data.get('issues', [])

                # Add the queried CWE ID to each issue found
                for issue in issues_on_page:
                    # Store the queried CWE
                    issue['queried_cwe'] = f"CWE-{target_cwe}"
                    all_found_issues.append(issue)

                print(
                    f"Fetched page {current_page}/{total_pages} ({len(issues_on_page)} issues)")

                # Check if this was the last page for this CWE
                if (current_page * PAGE_SIZE) >= total_issues_for_cwe:
                    break

                current_page += 1

            except requests.exceptions.Timeout:
                print(
                    f"Timeout occurred while fetching page {current_page} for CWE-{target_cwe}. Retrying...")
                time.sleep(5)  # Wait before retrying
                continue  # Retry the same page
            except requests.exceptions.RequestException as e:
                print(
                    f"Error fetching page {current_page} for CWE-{target_cwe}: {e}")
                # Decide if you want to break or retry
                break  # Stop processing this CWE on error
            except json.JSONDecodeError:
                print(
                    f"Error decoding JSON response for page {current_page} for CWE-{target_cwe}.")
                break  # Stop processing this CWE on error

        total_issues_overall += total_issues_for_cwe if total_issues_for_cwe > 0 else 0

    print(
        f"\nFinished fetching. Found a total of {len(all_found_issues)} issues across all queried CWEs.")
    return all_found_issues


def save_to_json(data, filename):
    """Saves the data to a JSON file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print(f"Successfully saved {len(data)} issues to {filename}")
    except IOError as e:
        print(f"Error saving data to {filename}: {e}")


if __name__ == "__main__":
    issues = fetch_sonar_issues_by_cwe(TARGET_CWES)
    if issues:
        save_to_json(issues, OUTPUT_FILE)
    else:
        print("No issues fetched or an error occurred.")
