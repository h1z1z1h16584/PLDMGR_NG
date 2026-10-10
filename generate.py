import hashlib
import json
import os
import re
import sys
import requests

LINKS_FILE = "links.txt"
OUTPUT_FILE = "payloads.json"
BROKEN_REPOS_FILE = "broken_repos.txt"
PAYLOAD_DIR = "payloads"
REPO_CATALOG_NAME = "Custom Payloads Archive"

# Dedicated category for manual/static files
STATIC_CATEGORY = "Archived (Legacy)"

VALID_EXTENSIONS = (".elf", ".bin", ".prx", ".lua")

token = os.getenv("GITHUB_TOKEN")
gh_repository = os.getenv("GITHUB_REPOSITORY", "your-username/your-repo")

github_headers = {
    "Accept": "application/vnd.github+json"
}
if token:
    github_headers["Authorization"] = f"Bearer {token}"

gitea_headers = {
    "Accept": "application/json"
}


def parse_repo_entry(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Etawen (Gitea / Forgejo instance)
    if "git.etawen.dev" in line.lower() or line.lower().startswith("etawen:"):
        cleaned = re.sub(r"^(?:https?://git\.etawen\.dev/|etawen:)", "", line, flags=re.IGNORECASE)
        cleaned = cleaned.rstrip("/").removesuffix(".git")
        parts = cleaned.split("/")
        if len(parts) >= 2:
            return ("etawen", parts[0].strip(), parts[1].strip())

    # GitHub or standard owner/repo
    cleaned = re.sub(
        r"^(?:https?://github\.com/|git@github\.com:|github:)",
        "",
        line,
        flags=re.IGNORECASE,
    )
    cleaned = cleaned.rstrip("/").removesuffix(".git")
    parts = cleaned.split("/")
    if len(parts) >= 2:
        return ("github", parts[0].strip(), parts[1].strip())

    return None


def fetch_target_releases(provider: str, owner: str, repo: str):
    if provider == "etawen":
        url = f"https://git.etawen.dev/api/v1/repos/{owner}/{repo}/releases"
        headers = gitea_headers
    else:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases"
        headers = github_headers

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 404:
            return None, "HTTP 404 (Repo or releases not found / deleted)"
        if response.status_code != 200:
            return None, f"HTTP {response.status_code}"

        releases = response.json()
        if not isinstance(releases, list):
            return None, "Invalid API payload format"

        latest_prerelease = next(
            (r for r in releases if r.get("prerelease") and not r.get("draft")), None
        )
        latest_official = next(
            (r for r in releases if not r.get("prerelease") and not r.get("draft")), None
        )

        targets = []
        if latest_official:
            targets.append(latest_official)
        if latest_prerelease:
            targets.append(latest_prerelease)

        if not targets:
            return None, "No published releases found"

        return targets, None

    except requests.exceptions.RequestException as e:
        return None, f"Network error: {str(e)}"


def is_ps4_asset(filename: str) -> bool:
    name_lower = filename.lower()
    return "ps4" in name_lower and "ps5" not in name_lower


def detect_category(repo_slug: str, filename: str, description: str, is_pre: bool) -> str:
    if is_pre:
        return "Pre-release"

    search_text = f"{repo_slug} {filename} {description}".lower()

    if any(k in search_text for k in ["ftp", "zftpd", "dns", "web", "websrv", "http", "server", "shsrv", "network"]):
        return "Networking"
    if any(k in search_text for k in ["kstuff", "etahen", "hen", "elfldr", "kernel", "klog", "debug", "ps5debug"]):
        return "Kernel & Exploitation"
    if any(k in search_text for k in ["dumper", "dump", "compress", "backup", "savemgr", "unrar", "7zip"]):
        return "Dumping & Backups"
    if any(k in search_text for k in ["cheat", "trainer", "cheatrunner"]):
        return "Cheats"
    if any(k in search_text for k in ["overlay", "dualsense", "controller", "anypad", "ds4"]):
        return "Controllers & Input"
    if any(k in search_text for k in ["sync", "time", "clock", "mount", "shadowmount", "upload", "manager", "prospero"]):
        return "System Utilities"

    return "Homebrew"


def download_binary(url: str, dest_path: str) -> bool:
    try:
        with requests.get(url, stream=True, timeout=60) as r:
            if r.status_code == 200:
                with open(dest_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        f.write(chunk)
                return True
            print(f"[!] Failed to download {url}: HTTP {r.status_code}")
    except Exception as e:
        print(f"[!] Download error for {url}: {e}")
    return False


def compute_sha256(filepath: str) -> str:
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def load_previous_payloads():
    if not os.path.exists(OUTPUT_FILE):
        return []

    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data.get("payloads", [])
    except Exception as e:
        print(f"[!] Warning reading existing {OUTPUT_FILE}: {e}")

    return []


def sanitize_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*]', '_', name)


def scan_static_404_payloads():
    """
    Finds all files in payloads/ starting with '404-' or '404 ' and registers
    them without checking remote releases.
    """
    static_entries = []
    if not os.path.exists(PAYLOAD_DIR):
        return static_entries

    for fname in sorted(os.listdir(PAYLOAD_DIR)):
        # Match '404-', '404_', or '404 '
        if re.match(r"^404[-_\s]", fname, re.IGNORECASE) and fname.lower().endswith(VALID_EXTENSIONS):
            local_path = os.path.join(PAYLOAD_DIR, fname)
            checksum = compute_sha256(local_path)
            hosted_url = f"https://raw.githubusercontent.com/{gh_repository}/main/{PAYLOAD_DIR}/{fname}"

            # Strip the 404 prefix cleanly
            clean_name = re.sub(r"^404[-_\s]+", "", fname, flags=re.IGNORECASE)
            base, _ = os.path.splitext(clean_name)
            display_title = base.replace("_", " ").replace("-", " ")

            entry = {
                "name": display_title,
                "filename": fname,
                "url": hosted_url,
                "description": f"Archived standalone payload: {clean_name}",
                "version": "Static",
                "category": STATIC_CATEGORY,
                "checksum": checksum
            }
            static_entries.append(entry)
            print(f"[+] Loaded static payload: {fname} -> {STATIC_CATEGORY}")

    return static_entries


def main():
    if not os.path.exists(LINKS_FILE):
        print(f"Error: {LINKS_FILE} not found.")
        sys.exit(1)

    os.makedirs(PAYLOAD_DIR, exist_ok=True)

    with open(LINKS_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entries = []
    for line in lines:
        entry = parse_repo_entry(line)
        if entry and entry not in entries:
            entries.append(entry)

    print(f"Found {len(entries)} repositories to process.")

    previous_payloads = load_previous_payloads()
    payload_list = []
    broken_repos = []
    seen_filenames = set()

    # 1. Process active repositories FIRST so standard categories lead the tabs
    for provider, owner, repo_name in entries:
        repo_slug = f"{owner}/{repo_name}"
        display_slug = f"{provider}:{repo_slug}"
        print(f"\nProcessing [{provider}]: {repo_slug}")

        releases, err = fetch_target_releases(provider, owner, repo_name)

        saved_fallback = [
            item for item in previous_payloads
            if repo_name.lower() in item.get("name", "").lower()
            or repo_name.lower() in item.get("filename", "").lower()
        ]

        if err:
            print(f"[!] Repo unreachable: {display_slug} ({err})")
            if saved_fallback:
                print(f"[+] Preserving {len(saved_fallback)} existing local payload(s) for {display_slug}")
                for fb in saved_fallback:
                    fname = fb.get("filename")
                    if os.path.exists(os.path.join(PAYLOAD_DIR, fname)) and fname not in seen_filenames:
                        seen_filenames.add(fname)
                        payload_list.append(fb)
                broken_repos.append(f"{display_slug} - {err} (Preserved {len(saved_fallback)} stored files)")
            else:
                broken_repos.append(f"{display_slug} - {err} (No previous files stored)")
            continue

        repo_payloads = []

        for release in releases:
            is_pre = release.get("prerelease", False)
            tag_name = release.get("tag_name", "").strip()
            release_title = release.get("name") or tag_name
            assets = release.get("assets", [])

            for asset in assets:
                orig_filename = asset.get("name", "")
                download_url = asset.get("browser_download_url") or asset.get("download_url", "")

                if not orig_filename.lower().endswith(VALID_EXTENSIONS):
                    continue

                if is_ps4_asset(orig_filename):
                    print(f"[-] Skipping PS4 asset: {orig_filename}")
                    continue

                base, ext = os.path.splitext(orig_filename)

                if tag_name and tag_name.lower() not in base.lower():
                    base_with_version = f"{base}_{tag_name}"
                else:
                    base_with_version = base

                if is_pre:
                    display_name = f"{repo_name} [Pre-release]"
                    file_name = sanitize_filename(f"{base_with_version} [Pre-release]{ext}")
                    desc = f"{release_title} [Pre-release] by {owner}"
                else:
                    display_name = repo_name
                    file_name = sanitize_filename(f"{base_with_version}{ext}")
                    desc = f"{release_title} by {owner}"

                if file_name in seen_filenames:
                    continue

                local_dest = os.path.join(PAYLOAD_DIR, file_name)

                if not os.path.exists(local_dest):
                    print(f"[+] Downloading: {orig_filename} -> {local_dest}")
                    success = download_binary(download_url, local_dest)
                    if not success:
                        continue
                else:
                    print(f"[*] Already cached: {file_name}")

                checksum = compute_sha256(local_dest)
                seen_filenames.add(file_name)

                hosted_url = f"https://raw.githubusercontent.com/{gh_repository}/main/{PAYLOAD_DIR}/{file_name}"
                category = detect_category(repo_slug, orig_filename, desc, is_pre)

                payload_entry = {
                    "name": display_name,
                    "filename": file_name,
                    "url": hosted_url,
                    "description": desc,
                    "version": tag_name if tag_name else "v1.0",
                    "category": category,
                    "checksum": checksum
                }
                repo_payloads.append(payload_entry)

        if not repo_payloads:
            print(f"[!] No valid payload binaries found for {display_slug}")
            if saved_fallback:
                for fb in saved_fallback:
                    fname = fb.get("filename")
                    if os.path.exists(os.path.join(PAYLOAD_DIR, fname)) and fname not in seen_filenames:
                        seen_filenames.add(fname)
                        payload_list.append(fb)
                broken_repos.append(f"{display_slug} - No assets in release (Preserved stored files)")
            else:
                broken_repos.append(f"{display_slug} - No valid binary assets")
        else:
            payload_list.extend(repo_payloads)

    # 2. Append the static 404 payloads AFTER all regular payloads
    static_payloads = scan_static_404_payloads()
    for sp in static_payloads:
        if sp["filename"] not in seen_filenames:
            seen_filenames.add(sp["filename"])
            payload_list.append(sp)

    # 3. Sort ordering:
    # Priority 0: Active payload categories (sorted alphabetically)
    # Priority 1: Pre-releases
    # Priority 2: Static/Archived (Legacy) payloads placed dead last
    def category_sort_rank(item):
        cat = item.get("category", "")
        if cat == STATIC_CATEGORY:
            return (2, cat, item["name"])
        elif cat == "Pre-release":
            return (1, cat, item["name"])
        return (0, cat, item["name"])

    payload_list.sort(key=category_sort_rank)

    # Core Rule: "name" must appear before "payloads"
    output_data = {
        "name": REPO_CATALOG_NAME,
        "payloads": payload_list
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    with open(BROKEN_REPOS_FILE, "w", encoding="utf-8") as f:
        for b in broken_repos:
            f.write(f"{b}\n")

    print(f"\nDone: {len(payload_list)} total payload(s) indexed in {OUTPUT_FILE}.")


if __name__ == "__main__":
    main()
