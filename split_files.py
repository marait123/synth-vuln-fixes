import pandas as pd
import re
import os
import json
from pathlib import Path
import numpy as np

# Load the parquet file
data = pd.read_parquet('./data/train-00000-of-00001.parquet')

# Helper function to extract code from markdown code blocks


def extract_code_from_markdown(text):
    if text is None:
        return None

    # Look for Python code blocks with triple backticks
    code_block_pattern = r"```python\s*([\s\S]*?)```"
    code_blocks = re.findall(code_block_pattern, text)

    if code_blocks:
        # Return the first code block found
        return code_blocks[0].strip()
    else:
        # If no code blocks with backticks found, return the original text
        return text.strip()

# Function to extract vulnerability type


def extract_vulnerability_type(conversation):
    for message in conversation:
        if message['role'] == 'user':
            # Look for vulnerability type in the format CWE-XXX
            match = re.search(
                r'Type:\s*(CWE-\d+|CVE-\d+-\d+|CWE-Unknown)', message['content'])
            if match:
                return match.group(1)
    return "Unknown"

# Function to extract original code


def extract_original_code(conversation):
    for message in conversation:
        if message['role'] == 'user':
            # Look for code sections in the user's message
            if "Original Code:" in message['content']:
                code_content = message['content'].split("Original Code:")[1]
                # Try to extract the code block
                if "Task:" in code_content:
                    code_content = code_content.split("Task:")[0].strip()
                return extract_code_from_markdown(code_content)
    return None

# Function to extract fixed code


def extract_fixed_code(conversation):
    for message in conversation:
        if message['role'] == 'assistant':
            # Extract code from the assistant's response (which might contain explanatory text)
            return extract_code_from_markdown(message['content'])
    return None

# Function to make data JSON serializable


def make_json_serializable(obj):
    if isinstance(obj, (np.ndarray, pd.Series)):
        return obj.tolist()
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(i) for i in obj]
    else:
        return obj


# Create a directory for storing the code samples
base_dir = Path("vulnerability_samples")
base_dir.mkdir(exist_ok=True)

# Process each row in the dataset
for idx, row in data.iterrows():
    # Convert conversation to standard Python types
    conversation = make_json_serializable(row['messages'])

    # Extract vulnerability type
    vuln_type = extract_vulnerability_type(conversation)

    # Create folder for this vulnerability type if it doesn't exist
    vuln_dir = base_dir / vuln_type
    vuln_dir.mkdir(exist_ok=True)

    # Extract original and fixed code
    original_code = extract_original_code(conversation)
    fixed_code = extract_fixed_code(conversation)

    if original_code and fixed_code:
        # Save the original code
        with open(vuln_dir / f"sample_{idx}_original.py", "w", encoding="utf-8") as f:
            f.write(original_code)

        # Save the fixed code
        with open(vuln_dir / f"sample_{idx}_fixed.py", "w", encoding="utf-8") as f:
            f.write(fixed_code)

        # Save metadata as JSON-serializable data
        metadata = {
            "vulnerability_type": vuln_type,
            "sample_id": int(idx) if isinstance(idx, np.integer) else idx,
            "conversation": conversation
        }

        with open(vuln_dir / f"sample_{idx}_metadata.json", "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

print(f"Saved code samples to {base_dir}")
