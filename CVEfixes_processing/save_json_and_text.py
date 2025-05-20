import json
import os

def save_cve_cwe_data_to_json(data_tuples, filename='cve_cwe_data.json'):
    """
    Save CVE-CWE tuples to a JSON file.
    
    Args:
        data_tuples: List of tuples in format ('CVE-ID', 'CWE-ID')
        filename: Output JSON filename
    """
    json_data = [{"cve_id": cve_id, "cwe_id": cwe_id} for cve_id, cwe_id in data_tuples]
    
    with open(filename, 'w') as json_file:
        json.dump(json_data, json_file, indent=4)
        print(f"Data saved to {filename}")

def save_cve_cwe_data_to_text(data_tuples, filename='cve_cwe_data.txt'):
    """
    Save CVE-CWE tuples to a text file.
    
    Args:
        data_tuples: List of tuples in format ('CVE-ID', 'CWE-ID')
        filename: Output text filename
    """
    with open(filename, 'w') as text_file:
        for cve_id, cwe_id in data_tuples:
            text_file.write(f"{cve_id},{cwe_id}\n")
        print(f"Data saved to {filename}")

def save_fixes_to_json(fixes, filename='fixes.json'):
    """
    Save fixes data to a JSON file.
    
    Args:
        fixes: List of tuples in format ('CVE-ID', 'CWE-ID')
        filename: Output JSON filename
    """
    with open(filename, 'w') as json_file:
        json.dump(fixes, json_file, indent=4)
        print(f"Fixes data saved to {filename}")
    
def save_fixes_to_text(fixes, filename='fixes.txt'):
    """
    Save fixes data to a text file.
    
    Args:
        fixes: List of tuples in format ('CVE-ID', 'CWE-ID')
        filename: Output text filename
    """
    with open(filename, 'w') as text_file:
        for cve_id, commit_id, gitHubURL in fixes:
            text_file.write(f"{cve_id},{commit_id},{gitHubURL}\n")
        print(f"Fixes data saved to {filename}")


def save_repos_json(repos_data, filename='repos.json'):
    """
    Save repository data to a JSON file.
    
    Args:
        fixes: List of tuples in format ('CVE-ID', 'CWE-ID')
        filename: Output JSON filename
    """
    with open(filename, 'w') as json_file:
        json.dump(repos_data, json_file, indent=4)
        print(f"Repository data saved to {filename}")

def save_repos_text(repos_data, filename='repos.txt'):
    """
    Save repository data to a text file.
    
    Args:
        fixes: List of tuples in format ('CVE-ID', 'CWE-ID')
        filename: Output text filename
    """
    with open(filename, 'w') as text_file:
        for url, name in repos_data:
            text_file.write(f"{url},{name}\n")
        print(f"Repository data saved to {filename}")

# Example usage
# if __name__ == "__main__":
#     # Example list of CVE-CWE tuples
#     cve_cwe_data = [
#         ('CVE-2007-10002', 'CWE-89'),
#         ('CVE-2010-1152', 'CWE-20'),
#         ('CVE-2010-1155', 'CWE-20'),
#         ('CVE-2010-1630', 'NVD-CWE-noinfo'),
#         ('CVE-2010-2060', 'NVD-CWE-Other'),
#         ('CVE-2012-4520', 'CWE-352')
#     ]
    
#     # Save to files
#     save_cve_cwe_data_to_json(cve_cwe_data)
#     save_cve_cwe_data_to_text(cve_cwe_data)
    
#     # Show the content of the generated files
#     print("\nJSON file content:")
#     with open('cve_cwe_data.json', 'r') as f:
#         print(f.read())
    
#     print("\nText file content:")
#     with open('cve_cwe_data.txt', 'r') as f:
#         print(f.read())