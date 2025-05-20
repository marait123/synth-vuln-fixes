**How to use it:**

1.  **Install dependencies:** You'll need the `requests` library. Install it using pip:
    ```bash
    pip install requests
    ```
2.  **Get a GitHub Personal Access Token (PAT):**
    - Go to your GitHub settings > Developer settings > Personal access tokens > Tokens (classic).
    - Generate a new token.
    - Grant the token the `security_events` scope (under `repo`). This is required to read security alerts.
3.  **Run the script:**

    - Open your terminal or command prompt.
    - Navigate to the directory where fetch_github_alerts.py is saved (`e:\masters\year 1 - semster 2\software-engineering\project\synth-vuln-fixes`).
    - Run the script using the following format:

    ```bash
    python fetch_github_alerts.py <repository_owner> <repository_name> --token <your_github_pat> --output <output_file.csv>
    ```

    - **Replace:**

      - `<repository_owner>` with the owner of the target repository (e.g., `octocat`).
      - `<repository_name>` with the name of the target repository (e.g., `Spoon-Knife`).
      - `<your_github_pat>` with the PAT you generated.
      - `<output_file.csv>` with the desired name for your output CSV file (optional, defaults to `github_security_alerts.csv`).

    - **Alternatively, set an environment variable:** You can set the `GITHUB_TOKEN` environment variable with your PAT instead of using the `--token` argument:
      - **Windows (cmd):** `set GITHUB_TOKEN=<your_github_pat>`
      - **Windows (PowerShell):** `$env:GITHUB_TOKEN="<your_github_pat>"`
      - **Linux/macOS:** `export GITHUB_TOKEN=<your_github_pat>`
        Then run:
      ```bash
      python fetch_github_alerts.py <repository_owner> <repository_name> -o <output_file.csv>
      ```

The script will fetch the code scanning alerts from the specified repository and save them into the designated CSV file. It handles pagination and provides feedback during the process.
