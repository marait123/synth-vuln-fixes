import requests
import csv
import os
import argparse
from datetime import datetime

# GitHub API endpoint for code scanning alerts
ALERTS_URL_TEMPLATE = "https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"

def fetch_alerts(owner, repo, token):
    """Fetches all code scanning alerts for a given repository."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28" # Recommended by GitHub docs
    }
    alerts = []
    url = ALERTS_URL_TEMPLATE.format(owner=owner, repo=repo)
    params = {'per_page': 100, 'state': 'open'} # Request max results per page, only open alerts initially. Can be changed.

    print(f"Fetching alerts from {url}...")

    while url:
        try:
            # Use params only for the first request, subsequent URLs from pagination include them
            current_params = params if params else None
            response = requests.get(url, headers=headers, params=current_params)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()
            if not isinstance(data, list):
                print(f"Error: Unexpected API response format: {data}")
                return None
            alerts.extend(data)
            print(f"Fetched {len(data)} alerts. Total fetched: {len(alerts)}")

            # Handle pagination
            if 'next' in response.links:
                url = response.links['next']['url']
                params = None # Params are included in the 'next' URL
            else:
                url = None # No more pages

        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error fetching alerts: {e}")
            print(f"Response status: {e.response.status_code}")
            print(f"Response body: {e.response.text}")
            if e.response.status_code == 404:
                print("Repository not found or code scanning not enabled/no alerts found.")
            elif e.response.status_code == 401:
                 print("Authentication failed. Check your GitHub token and its permissions (needs 'security_events' scope).")
            elif e.response.status_code == 403:
                 print("Forbidden. Check token permissions or rate limits.")
            return None # Indicate failure
        except requests.exceptions.RequestException as e:
            print(f"Network or request error fetching alerts: {e}")
            return None # Indicate failure
        except Exception as e:
            print(f"An unexpected error occurred during fetch: {e}")
            return None

    print(f"Finished fetching. Total alerts found: {len(alerts)}")
    return alerts

def save_to_csv(alerts, filename="github_security_alerts.csv"):
    """Saves the fetched alerts to a CSV file."""
    if alerts is None:
        print("Alert fetching failed. Cannot save to CSV.")
        return
    if not alerts:
        print("No alerts found or fetched to save.")
        return

    # Define the headers based on potential fields in the alert object
    # Adjust these based on the actual data you need
    headers = [
        'number', 'created_at', 'updated_at', 'url', 'html_url',
        'state', 'dismissed_by', 'dismissed_at', 'dismissed_reason', 'fixed_at',
        'rule_id', 'rule_severity', 'rule_description', 'rule_name', 'rule_tags',
        'tool_name', 'tool_version', 'most_recent_instance_ref', 'most_recent_instance_analysis_key',
        'most_recent_instance_environment', 'most_recent_instance_category',
        'most_recent_instance_location_path',
        'most_recent_instance_location_start_line', 'most_recent_instance_location_end_line',
        'most_recent_instance_location_start_column', 'most_recent_instance_location_end_column',
        'most_recent_instance_message_text', 'most_recent_instance_state',
        'most_recent_instance_classifications'
    ]

    print(f"Saving alerts to {filename}...")
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore') # Ignore extra fields from API
            writer.writeheader()

            for alert in alerts:
                # Flatten the nested structure for CSV
                row = {
                    'number': alert.get('number'),
                    'created_at': alert.get('created_at'),
                    'updated_at': alert.get('updated_at'),
                    'url': alert.get('url'),
                    'html_url': alert.get('html_url'),
                    'state': alert.get('state'),
                    'dismissed_by': alert.get('dismissed_by', {}).get('login') if alert.get('dismissed_by') else None,
                    'dismissed_at': alert.get('dismissed_at'),
                    'dismissed_reason': alert.get('dismissed_reason'),
                    'fixed_at': alert.get('fixed_at'),
                    'rule_id': alert.get('rule', {}).get('id'),
                    'rule_severity': alert.get('rule', {}).get('severity'),
                    'rule_description': alert.get('rule', {}).get('description'),
                    'rule_name': alert.get('rule', {}).get('name'),
                    'rule_tags': ','.join(alert.get('rule', {}).get('tags', [])) if alert.get('rule', {}).get('tags') else None,
                    'tool_name': alert.get('tool', {}).get('name'),
                    'tool_version': alert.get('tool', {}).get('version'),
                    'most_recent_instance_ref': alert.get('most_recent_instance', {}).get('ref'),
                    'most_recent_instance_analysis_key': alert.get('most_recent_instance', {}).get('analysis_key'),
                    'most_recent_instance_environment': alert.get('most_recent_instance', {}).get('environment'),
                    'most_recent_instance_category': alert.get('most_recent_instance', {}).get('category'),
                    'most_recent_instance_location_path': alert.get('most_recent_instance', {}).get('location', {}).get('path'),
                    'most_recent_instance_location_start_line': alert.get('most_recent_instance', {}).get('location', {}).get('start_line'),
                    'most_recent_instance_location_end_line': alert.get('most_recent_instance', {}).get('location', {}).get('end_line'),
                    'most_recent_instance_location_start_column': alert.get('most_recent_instance', {}).get('location', {}).get('start_column'),
                    'most_recent_instance_location_end_column': alert.get('most_recent_instance', {}).get('location', {}).get('end_column'),
                    'most_recent_instance_message_text': alert.get('most_recent_instance', {}).get('message', {}).get('text'),
                    'most_recent_instance_state': alert.get('most_recent_instance', {}).get('state'),
                    'most_recent_instance_classifications': ','.join(alert.get('most_recent_instance', {}).get('classifications', [])) if alert.get('most_recent_instance', {}).get('classifications') else None
                }
                writer.writerow(row)
        print(f"Successfully saved {len(alerts)} alerts to {filename}")
    except IOError as e:
        print(f"Error writing to CSV file {filename}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during CSV writing: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch GitHub Code Scanning alerts for a repository and save to CSV.",
        epilog="Example: python fetch_github_alerts.py octocat Spoon-Knife -o my_alerts.csv"
    )
    parser.add_argument("owner", help="The owner of the GitHub repository (e.g., 'octocat').")
    parser.add_argument("repo", help="The name of the GitHub repository (e.g., 'Spoon-Knife').")
    parser.add_argument(
        "-t", "--token",
        help="GitHub Personal Access Token (PAT) with 'security_events' scope. Reads from GITHUB_TOKEN environment variable if not provided."
    )
    parser.add_argument(
        "-o", "--output",
        default="github_security_alerts.csv",
        help="Output CSV file name (default: github_security_alerts.csv)."
    )
    # Optional: Add arguments to filter alerts by state (e.g., open, fixed, dismissed) if needed

    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")

    if not token:
        print("Error: GitHub token not provided.")
        print("Please set the GITHUB_TOKEN environment variable or use the --token argument.")
        print("The token requires the 'security_events' scope.")
        exit(1)

    if not args.owner or not args.repo:
         print("Error: Repository owner and name are required.")
         parser.print_help()
         exit(1)

    alerts_data = fetch_alerts(args.owner, args.repo, token)

    if alerts_data is not None:
        save_to_csv(alerts_data, args.output)
    else:
        print("Failed to fetch or process alerts. CSV file not created.")
        exit(1)

    print("Script finished.")
