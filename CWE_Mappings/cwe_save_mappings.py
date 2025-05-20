import requests
import json
from typing import Dict, Optional

class CWEHierarchyAnalyzer:
    def __init__(self):
        self.base_url = "https://cwe-api.mitre.org/api/v1"
        self.pillar_mapping = {}

    def normalize_cwe_id(self, cwe_id: str) -> str:
        return cwe_id.replace('CWE-', '') if isinstance(cwe_id, str) else str(cwe_id)

    def get_pillar_parent(self, child_id: str) -> Optional[str]:
        try:
            child_id = self.normalize_cwe_id(child_id)
            current_id = child_id
            visited = set()

            while True:
                url = f"{self.base_url}/cwe/{current_id}/parents?view=1000"
                response = requests.get(url)
                response.raise_for_status()
                json_data = response.json()

                if not json_data:
                    return None

                parent_type = json_data[0]["Type"]
                parent_id = str(json_data[0]["ID"])

                if parent_type == "pillar_weakness":
                    return f"CWE-{parent_id}"

                if parent_id in visited:
                    return None

                visited.add(parent_id)
                current_id = parent_id

        except requests.exceptions.RequestException as e:
            print(f"Error fetching data for CWE-{child_id}: {e}")
            return None

    def build_pillar_mapping(self, start: int = 1, end: int = 2000) -> Dict[str, str]:
        mapping = {}
        for cwe_id in range(start, end + 1):
            pillar_parent = self.get_pillar_parent(str(cwe_id))
            if pillar_parent:
                mapping[f"CWE-{cwe_id}"] = pillar_parent
            if cwe_id % 100 == 0:
                print(f"Processed up to CWE-{cwe_id}")
        return mapping

def save_mapping_to_file(mapping: Dict[str, str], filename: str = "cwe_pillar_mapping.json"):
    """Save the CWE mapping to a JSON file"""
    with open(filename, 'w') as f:
        json.dump(mapping, f, indent=4)
    print(f"Mapping saved to {filename}")

def main():
    analyzer = CWEHierarchyAnalyzer()
    
    # Build mapping for range 1-1500 (or adjust range as needed)
    print("Building CWE pillar mapping...")
    mapping = analyzer.build_pillar_mapping(1, 1500)
    
    # Save to JSON file
    save_mapping_to_file(mapping)
    
    # Print some statistics
    print(f"\nTotal mappings found: {len(mapping)}")
    print("\nSample of first 5 entries:")
    for child, pillar in list(mapping.items())[:5]:
        print(f"{child} -> {pillar}")

if __name__ == "__main__":
    main()