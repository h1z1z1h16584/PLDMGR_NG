from datetime import datetime
import hashlib
import json
import os
import re
import sys
from urllib.parse import quote
import requests

LINKS_FILE = "links.txt"
OUTPUT_FILE = "payloads.json"
BROKEN_REPOS_FILE = "broken_repos.txt"
BASE_PAYLOAD_DIR = "payloads"
REPO_CATALOG_NAME = "Custom Payloads Archive"

STATIC_CATEGORY = "~ Archived"
PRE_RELEASE_CATEGORY = "Pre-release"

# Locking archived payloads prevents update prompts in the manager UI
ARCHIVED_VERSION = "v99.0"
ARCHIVED_DATE = "2000-01-01"

VALID_EXTENSIONS = (".elf", ".bin", ".prx", ".lua")
PRE_RELEASE_KEYWORDS = ("beta", "alpha", "rc", "preview", "test", "fix")

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


def slugify(text: str) -> str:
    """Creates a stable ID matching [a-z0-9._-]."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    return text.strip("-")


def truncate_utf8_bytes(text: str, max_bytes: int = 2044) -> str:
    """Safely truncates text to fit within the 2047 UTF-8 byte budget."""
    if not text:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text

    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated.rstrip() + "..."


def parse_repo_entry(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Etawen (Gitea / Forgejo)
    if "git.etawen.dev" in line.lower() or line.lower().startswith("etawen:"):
        cleaned = re.sub(r"^(?:https?://git\.etawen\.dev/|etawen:)", "", line, flags=re.IGNORECASE)
        cleaned = cleaned.rstrip("/").removesuffix(".git")
        parts = cleaned.split("/")
        if len(parts) >= 2:
            return ("etawen", parts[0].strip(), parts[1].strip())

    # GitHub
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


def is_release_prerelease(release: dict) -> bool:
    if release.get("prerelease"):
        return True

    tag = release.get("tag_name", "").lower()
    name = (release.get("name") or "").lower()
    return any(kw in tag or kw in name for kw in PRE_RELEASE_KEYWORDS)


def extract_date(raw_date_str: str) -> str:
    if not raw_date_str:
        return ""
    try:
        return raw_date_str.split("T")[0]
    except Exception:
        return str(raw_date_str)[:10]


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

        # Exclude draft releases
        valid_releases = [r for r in releases if not r.get("draft")]

        # Sort descending by published_at (newest published first)
        valid_releases.sort(
            key=lambda r: r.get("published_at") or r.get("created_at") or "",
            reverse=True
        )

        latest_prerelease = next(
            (r for r in valid_releases if is_release_prerelease(r)), None
        )
        latest_official = next(
            (r for r in valid_releases if not is_release_prerelease(r)), None
        )

        targets = []
        if latest_official:
            targets.append(latest_official)
        if latest_prerelease and latest_prerelease != latest_official:
            latest_prerelease["prerelease"] = True
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
        return PRE_RELEASE_CATEGORY

    search_text = f"{repo_slug} {filename} {description}".lower()

    if any(k in search_text for k in ["ftp", "zftpd", "dns", "web", "websrv", "http", "server", "shsrv", "network", "upload"]):
        return "Networking & Servers"
    if any(k in search_text for k in ["kstuff", "etahen", "hen", "elfldr", "kernel", "klog", "debug", "ps5debug"]):
        return "Kernel & Exploitation"
    if any(k in search_text for k in ["dumper", "dump", "compress", "backup", "savemgr", "unrar", "7zip"]):
        return "Dumping & Backups"
    if any(k in search_text for k in ["cheat", "trainer", "cheatrunner"]):
        return "Cheats"
    if any(k in search_text for k in ["overlay", "dualsense", "controller", "anypad", "ds4"]):
        return "Controllers & Input"
    if any(k in search_text for k in ["sync", "time", "clock", "mount", "shadowmount", "manager", "prospero"]):
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
    return sha.hexdigest().lower()


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


def scan_static_archived_payloads():
    """
    Scans the static/archived directory for manual binaries,
    giving them a stable ID, v99.0 version, and the fixed historical ARCHIVED_DATE.
    """
    static_entries = []
    possible_dirs = [
        os.path.join(BASE_PAYLOAD_DIR, STATIC_CATEGORY),
        os.path.join(BASE_PAYLOAD_DIR, "Archived"),
        os.path.join(BASE_PAYLOAD_DIR, "static")
    ]

    target_dir = None
    for d in possible_dirs:
        if os.path.exists(d):
            target_dir = d
            break

    if not target_dir:
        return static_entries

    folder_name = os.path.basename(target_dir)

    for fname in sorted(os.listdir(target_dir)):
        if fname.lower().endswith(VALID_EXTENSIONS):
            local_path = os.path.join(target_dir, fname)
            checksum = compute_sha256(local_path)

            encoded_folder = quote(folder_name)
            encoded_fname = quote(fname)
            hosted_url = f"https://raw.githubusercontent.com/{gh_repository}/main/{BASE_PAYLOAD_DIR}/{encoded_folder}/{encoded_fname}"

            base, _ = os.path.splitext(fname)
            display_title = base.replace("_", " ").replace("-", " ")
            payload_id = slugify(f"archived-{base}")

            entry = {
                "id": payload_id,
                "name": display_title,
                "filename": fname,
                "url": hosted_url,
                "source": hosted_url,
                "source_direct": hosted_url,
                "description": f"Archived standalone payload: {fname}",
                "last_update": ARCHIVED_DATE,
                "version": ARCHIVED_VERSION,
                "author": "Community Archive",
                "category": STATIC_CATEGORY,
                "checksum": checksum
            }
            static_entries.append(entry)
            print(f"[+] Loaded archived payload: {fname} (id={payload_id}, date={ARCHIVED_DATE})")

    return static_entries


def main():
    if not os.path.exists(LINKS_FILE):
        print(f"Error: {LINKS_FILE} not found.")
        sys.exit(1)

    os.makedirs(BASE_PAYLOAD_DIR, exist_ok=True)
    os.makedirs(os.path.join(BASE_PAYLOAD_DIR, STATIC_CATEGORY), exist_ok=True)

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

    # 1. Process active repositories
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
                print(f"[+] Preserving fallback items for {display_slug}")
                for fb in saved_fallback:
                    fname = fb.get("filename")
                    cat = fb.get("category", "Homebrew")
                    expected_path = os.path.join(BASE_PAYLOAD_DIR, cat, fname)
                    if (os.path.exists(expected_path) or os.path.exists(os.path.join(BASE_PAYLOAD_DIR, fname))) and fname not in seen_filenames:
                        seen_filenames.add(fname)
                        payload_list.append(fb)
                broken_repos.append(f"{display_slug} - {err} (Preserved stored files)")
            else:
                broken_repos.append(f"{display_slug} - {err} (No previous files stored)")
            continue

        repo_payloads = []

        if provider == "etawen":
            release_source_page = f"https://git.etawen.dev/{owner}/{repo_name}/releases"
        else:
            release_source_page = f"https://github.com/{owner}/{repo_name}/releases"

        for release in releases:
            is_pre = release.get("prerelease", False)
            tag_name = release.get("tag_name", "").strip()
            release_title = release.get("name") or tag_name
            raw_date = release.get("published_at") or release.get("created_at") or ""
            last_update = extract_date(raw_date)
            release_notes = truncate_utf8_bytes(release.get("body") or "")
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
                    payload_id = slugify(f"{repo_name}-{base}-prerelease")
                else:
                    display_name = repo_name
                    file_name = sanitize_filename(f"{base_with_version}{ext}")
                    desc = f"{release_title} by {owner}"
                    payload_id = slugify(f"{repo_name}-{base}")

                if file_name in seen_filenames:
                    continue

                category = detect_category(repo_slug, orig_filename, desc, is_pre)
                category_dir = os.path.join(BASE_PAYLOAD_DIR, category)
                os.makedirs(category_dir, exist_ok=True)
                local_dest = os.path.join(category_dir, file_name)

                if not os.path.exists(local_dest):
                    print(f"[+] Downloading: {orig_filename} -> {local_dest}")
                    success = download_binary(download_url, local_dest)
                    if not success:
                        continue
                else:
                    print(f"[*] Already cached: {category}/{file_name}")

                checksum = compute_sha256(local_dest)
                seen_filenames.add(file_name)

                encoded_category = quote(category)
                encoded_filename = quote(file_name)
                hosted_url = f"https://raw.githubusercontent.com/{gh_repository}/main/{BASE_PAYLOAD_DIR}/{encoded_category}/{encoded_filename}"

                payload_entry = {
                    "id": payload_id,
                    "name": display_name,
                    "filename": file_name,
                    "url": hosted_url,
                    "source": release_source_page,
                    "source_direct": download_url,
                    "description": desc,
                    "last_update": last_update,
                    "version": tag_name if tag_name else "v1.0",
                    "author": owner,
                    "category": category,
                    "checksum": checksum
                }

                if release_notes:
                    payload_entry["release_notes"] = release_notes

                repo_payloads.append(payload_entry)

        if not repo_payloads:
            print(f"[!] No valid payload binaries found for {display_slug}")
            if saved_fallback:
                for fb in saved_fallback:
                    fname = fb.get("filename")
                    cat = fb.get("category", "Homebrew")
                    expected_path = os.path.join(BASE_PAYLOAD_DIR, cat, fname)
                    if (os.path.exists(expected_path) or os.path.exists(os.path.join(BASE_PAYLOAD_DIR, fname))) and fname not in seen_filenames:
                        seen_filenames.add(fname)
                        payload_list.append(fb)
                broken_repos.append(f"{display_slug} - No assets in release (Preserved stored files)")
            else:
                broken_repos.append(f"{display_slug} - No valid binary assets")
        else:
            payload_list.extend(repo_payloads)

    # 2. Append static archived payloads
    static_payloads = scan_static_archived_payloads()
    for sp in static_payloads:
        if sp["filename"] not in seen_filenames:
            seen_filenames.add(sp["filename"])
            payload_list.append(sp)

    # 3. Sort ordering (Active categories first, Pre-release, ~ Archived last)
    def category_sort_rank(item):
        cat = item.get("category", "")
        if cat == STATIC_CATEGORY:
            return (2, cat, item["name"])
        elif cat == PRE_RELEASE_CATEGORY:
            return (1, cat, item["name"])
        return (0, cat, item["name"])

    payload_list.sort(key=category_sort_rank)

    output_data = {
        "name": REPO_CATALOG_NAME,
        "payloads": payload_list
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    with open(BROKEN_REPOS_FILE, "w", encoding="utf-8") as f:
        for b in broken_repos:
            f.write(f"{b}\n")

    print(f"\nDone: {len(payload_list)} payloads processed. Archived items assigned historical date {ARCHIVED_DATE}.")


if __name__ == "__main__":
    main()
