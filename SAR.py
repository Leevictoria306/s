import os
import subprocess
import requests
import argparse

# === CLI args ===
parser = argparse.ArgumentParser(description="Scan all repos of a GitHub user/org with Gitleaks")
parser.add_argument("--user", required=True, help="GitHub username or org")
parser.add_argument("--token", help="GitHub token for private repos")
args = parser.parse_args()

GITHUB_USER = args.user
GITHUB_TOKEN = args.token
CONFIG_FILE = "custgitleaks.toml"
OUTPUT_DIR = "gitleaks_reports"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# === Ensure customgitleaks.toml exists ===
if not os.path.exists(CONFIG_FILE):
    print(f"[!] {CONFIG_FILE} not found. Downloading...")
    url = "https://raw.githubusercontent.com/Leevictoria306/s/refs/heads/main/custgitleaks.toml"
    r = requests.get(url)
    if r.status_code == 200:
        with open(CONFIG_FILE, "w") as f:
            f.write(r.text)
        print(f"[+] Downloaded {CONFIG_FILE}")
    else:
        print(f"[x] Failed to download config from {url}")
        exit(1)

# === Get repos via GitHub API ===
headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
repos = []
page = 1
while True:
    url = f"https://api.github.com/users/{GITHUB_USER}/repos?per_page=100&page={page}"
    r = requests.get(url, headers=headers)
    data = r.json()
    if not data or "message" in data:  # no more repos or error
        break
    repos.extend([repo["clone_url"] for repo in data])
    page += 1

print(f"\n[+] Found {len(repos)} repos for {GITHUB_USER}")

# === Colors ===
BOLD_YELLOW = "\033[1;33m"
RESET = "\033[0m"

# === Clone + run gitleaks ===
for repo_url in repos:
    name = repo_url.split("/")[-1].replace(".git", "")
    print(f"\n{BOLD_YELLOW}>>> Scanning {name} ...{RESET}")

    # clone
    subprocess.run(["git", "clone", "--quiet", repo_url, name], check=True)

    # run gitleaks
    report_path = os.path.join(OUTPUT_DIR, f"{name}.json")
    subprocess.run([
        "gitleaks", "detect",
        "--source", name,
        "--config", CONFIG_FILE,
        "--report-format", "json",
        "--report-path", report_path,
        "--verbose",
        "--no-banner"
    ], check=False)

    # cleanup repo
    subprocess.run(["rm", "-rf", name])

print(f"\n✅ Done! Reports saved in {OUTPUT_DIR}/")
