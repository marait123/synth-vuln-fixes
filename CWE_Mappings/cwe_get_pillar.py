import requests
from typing import Optional

def get_cwe_pillar(cwe_id: str) -> Optional[str]:
    """
    Get the pillar parent ID for a given CWE ID.
    
    Args:
        cwe_id (str): CWE ID in either format: '22' or 'CWE-22'
        
    Returns:
        Optional[str]: Pillar parent ID in 'CWE-XXX' format or None if not found
        
    Examples:
        >>> get_cwe_pillar('22')
        'CWE-669'
        >>> get_cwe_pillar('CWE-22')
        'CWE-669'
    """
    
    # Normalize the CWE ID
    normalized_id = cwe_id.replace('CWE-', '') if isinstance(cwe_id, str) else str(cwe_id)
    base_url = "https://cwe-api.mitre.org/api/v1"
    visited_ids = set()  # Track visited IDs to prevent infinite loops
    
    try:
        current_id = normalized_id
        
        while True:
            # Construct API URL
            url = f"{base_url}/cwe/{current_id}/parents?view=1000"
            
            # Make API request
            response = requests.get(url)
            response.raise_for_status()  # Raise exception for bad status codes
            json_data = response.json()
            
            # Check if we got any data
            if not json_data:
                return None
            
            # Extract parent information
            parent_type = json_data[0]["Type"]
            parent_id = str(json_data[0]["ID"])
            
            # If we found a pillar, return it
            if parent_type == "pillar_weakness":
                return f"CWE-{parent_id}"
            
            # Check for cycles
            if parent_id in visited_ids:
                return None
            
            # Add current ID to visited set
            visited_ids.add(parent_id)
            
            # Move up to parent
            current_id = parent_id
            
    except requests.exceptions.RequestException as e:
        print(f"Error accessing CWE API: {e}")
        return None
    except (KeyError, IndexError) as e:
        print(f"Error parsing API response: {e}")
        return None

def main():
    # Test cases
    test_cases = [
        "22",
        "CWE-22",
        "89",
        "CWE-89",
        "287",
        "invalid-id",
        "9999"  # Non-existent CWE
    ]
    
    print("Testing CWE Pillar Lookup:")
    print("-" * 40)
    
    for cwe in test_cases:
        pillar = get_cwe_pillar(cwe)
        print(f"Input: {cwe:10} → Pillar: {pillar if pillar else 'Not found'}")

if __name__ == "__main__":
    main()