import json


def extract_fixes_of_vulnerabilities_that_have_cwe():
    """
    Extracts the fixes of vulnerabilities that have CWE from the JSON file and saves them to a text file.
    """
    with open("cve_cwe_mapping/cve_cwe_data.json", "r") as f:
        cve_cwe_mappings = json.load(f)
    
    # print("CVE CWE Mapping:", cve_cwe_mappings[0])
    cve_cwe_mappings_dict = {}
    for cve_cwe_mapping in cve_cwe_mappings:
        cwe_id = cve_cwe_mapping.get("cwe_id")
        cve_id = cve_cwe_mapping.get("cve_id")
        if cwe_id.startswith("CWE-"):
            if cve_id not in cve_cwe_mappings_dict:
                cve_cwe_mappings_dict[cve_id] = []
            cve_cwe_mappings_dict[cve_id].append(cwe_id)

    # save the cve_cwe_mappings_dict to a json file
    with open("cve_cwe_mapping/cve_cwe_mappings_dict.json", "w") as f:
        json.dump(cve_cwe_mappings_dict, f, indent=4)
    
    with open("repos_fixes/fixes.json", "r") as f:
        all_fixes = json.load(f)
    
    filtered_fixes = []
    for fix in all_fixes:
        cve_id = fix[0]
        if cve_cwe_mappings_dict.get(cve_id):
            filtered_fixes.append(fix)

    # save the filtered fixes to a json file
    with open("repos_fixes/filtered_fixes.json", "w") as f:
        json.dump(filtered_fixes, f, indent=4)
    # save the filtered fixes to a text file
    with open("repos_fixes/filtered_fixes.txt", "w") as f:
        for fix in filtered_fixes:
            f.write(f"{fix}\n")
    print(f"Filtered fixes saved to repos_fixes/filtered_fixes.txt and repos_fixes/filtered_fixes.json")

if __name__ == "__main__":
    extract_fixes_of_vulnerabilities_that_have_cwe()
