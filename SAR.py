import os
import subprocess
import requests
import argparse
import shutil
import json

# === CLI args ===
parser = argparse.ArgumentParser(description="Scan repos with Gitleaks")
parser.add_argument("--user", help="GitHub username or org (scan all repos)")
parser.add_argument("--repo", help="Single GitHub repo URL (e.g. https://github.com/user/repo.git)")
parser.add_argument("--token", help="GitHub token for private repos")
parser.add_argument("--exclude-forks", action="store_true", help="Exclude forked repos (only applies with --user)")
args = parser.parse_args()

if not args.user and not args.repo:
    parser.error("You must specify either --user or --repo")

GITHUB_USER = args.user
GITHUB_TOKEN = args.token
CONFIG_FILE = "custGL.toml"
OUTPUT_DIR = "gitleaks_reports"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# === Colors ===
PURPLE = "\033[1;35m"
BOLD_YELLOW = "\033[1;33m"
IRed = "\[\033[0;91m\]"
RESET = "\033[0m"

# === Check if gitleaks is installed ===
if not shutil.which("gitleaks"):
    print("[!] gitleaks not found. Installing...")
    subprocess.run([
        "wget", "-q",
        "https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz"
    ], check=True)
    subprocess.run(["tar", "-xzf", "gitleaks_8.28.0_linux_x64.tar.gz"], check=True)
    subprocess.run(["mv", "gitleaks", "/usr/local/bin/"], check=True)
    subprocess.run(["chmod", "+x", "/usr/local/bin/gitleaks"], check=True)
    print("[+] gitleaks installed successfully")

# === Ensure config exists ===
if not os.path.exists(CONFIG_FILE):
    print(f"[!] {CONFIG_FILE} not found. Downloading...")
    url = "https://raw.githubusercontent.com/Leevictoria306/s/refs/heads/main/custGL.toml"
    r = requests.get(url)
    if r.status_code == 200:
        with open(CONFIG_FILE, "w") as f:
            f.write(r.text)
        print(f"[+] Downloaded {CONFIG_FILE}")
    else:
        print(f"[x] Failed to download config from {url}")
        exit(1)

# === Build repo list ===
repos = []

if args.repo:
    repos = [args.repo]
else:
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    page = 1
    while True:
        url = f"https://api.github.com/users/{GITHUB_USER}/repos?per_page=100&page={page}"
        r = requests.get(url, headers=headers)
        data = r.json()
        if not data or "message" in data:
            break
        for repo in data:
            if args.exclude_forks and repo.get("fork"):
                continue
            repos.append(repo["clone_url"])
        page += 1
    print(f"\n[+] Found {len(repos)} repos for {GITHUB_USER} (exclude forks: {args.exclude_forks})")

# === Deduplication store ===
seen_secrets = set()
all_findings = []

# === Clone + run gitleaks ===
for repo_url in repos:
    name = repo_url.split("/")[-1].replace(".git", "")
    print(f"\n{PURPLE}[+] >>> Scanning {name}{RESET}")

    # cleanup old repo if exists
    if os.path.exists(name):
        shutil.rmtree(name)

    # clone repo fresh
    subprocess.run(["git", "clone", "--quiet", repo_url, name], check=True)

    # run gitleaks (JSON only, no banner)
    report_path = os.path.join(OUTPUT_DIR, f"{name}.json")
    subprocess.run([
        "gitleaks", 
        "git", name,
        "--config", CONFIG_FILE,
        "--report-format", "json",
        "--report-path", report_path,
        "--no-banner"
    ], check=False)

    # parse results
    if os.path.exists(report_path):
        try:
            with open(report_path, "r") as f:
                findings = json.load(f)

            unique_findings = []
            for finding in findings:
                secret_value = finding.get("Secret")
                if secret_value and secret_value not in seen_secrets:
                    seen_secrets.add(secret_value)
                    unique_findings.append(finding)
                    all_findings.append(finding)

                    # === pretty print finding ===
                    print(f"Finding:           {finding.get('Match')}")
                    print(f"Secret:            {IRed}{secret_value}{RESET}")
                    print(f"RuleID:            {BOLD_YELLOW}{finding.get('RuleID')}{RESET}")
                    print(f"Entropy:           {finding.get('Entropy')}")
                    print(f"Date:              {finding.get('Date')}")
                    print(f"Link:              {PURPLE}{finding.get('Link')}{RESET}\n")

            # overwrite with deduped findings
            with open(report_path, "w") as f:
                json.dump(unique_findings, f, indent=2)

        except Exception as e:
            print(f"[x] Failed to parse report for {name}: {e}")

    # cleanup repo
    shutil.rmtree(name, ignore_errors=True)

# === Save global merged report ===
merged_report_path = os.path.join(OUTPUT_DIR, "all_repos_deduped.json")
with open(merged_report_path, "w") as f:
    json.dump(all_findings, f, indent=2)

print(f"\n✅ Done! Reports saved in {OUTPUT_DIR}/ (deduplicated)")
print(f"   Global deduped report: {merged_report_path}")

