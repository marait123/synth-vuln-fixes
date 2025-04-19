import requests
import json
import math

# --- Configuration ---
SONAR_URL = "http://localhost:9000"
# Replace with your actual token if different
SONAR_TOKEN = "sqa_a202aaf2844423f4dd1e63a7a0c2493eb8091ac3"
PROJECT_KEY = "synth-vuln-fixes"
# ISSUE_TYPES = "VULNERABILITY" # Commented out as we fetch all types now
PAGE_SIZE = 500  # Max allowed by SonarQube API
OUTPUT_FILE = "all_sonar_issues.json"
# ---------------------


def fetch_sonar_issues():
    """Fetches all issues for the project from SonarQube."""
    all_issues = []
    current_page = 1
    total_issues = -1  # Initialize to -1 to enter the loop

    print(
        f"Fetching ALL issues for project '{PROJECT_KEY}' from {SONAR_URL}...")

    while True:
        api_endpoint = f"{SONAR_URL}/api/issues/search"
        params = {
            "componentKeys": PROJECT_KEY,
            # "types": ISSUE_TYPES, # Removed to fetch all issue types
            "ps": PAGE_SIZE,
            "p": current_page
        }
        # Use token for authentication (as username, empty password)
        auth = (SONAR_TOKEN, '')

        try:
            response = requests.get(
                api_endpoint, params=params, auth=auth, timeout=60)  # Added timeout
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

            data = response.json()

            if total_issues == -1:  # First request
                total_issues = data.get('total', 0)
                total_pages = math.ceil(total_issues / PAGE_SIZE)
                print(
                    f"Found {total_issues} issues across {total_pages} pages.")

            issues_on_page = data.get('issues', [])
            all_issues.extend(issues_on_page)

            print(
                f"Fetched page {current_page}/{total_pages} ({len(issues_on_page)} issues)")

            # Check if this was the last page
            if (current_page * PAGE_SIZE) >= total_issues:
                break

            current_page += 1

        except requests.exceptions.RequestException as e:
            print(f"Error fetching page {current_page}: {e}")
            # Decide if you want to break or retry
            break
        except json.JSONDecodeError:
            print(f"Error decoding JSON response for page {current_page}.")
            break

    return all_issues


def save_to_json(data, filename):
    """Saves the data to a JSON file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print(f"Successfully saved {len(data)} issues to {filename}")
    except IOError as e:
        print(f"Error saving data to {filename}: {e}")


if __name__ == "__main__":
    issues = fetch_sonar_issues()
    if issues:
        save_to_json(issues, OUTPUT_FILE)
    else:
        print("No issues fetched or an error occurred.")
