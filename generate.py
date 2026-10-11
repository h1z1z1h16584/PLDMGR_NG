# ----------------------------------------------------
# PASTE RIGHT AFTER: parse_repo_entry(...)
# PASTE RIGHT BEFORE: is_ps4_asset(...)
# ----------------------------------------------------

PRE_RELEASE_KEYWORDS = ("beta", "alpha", "rc", "preview", "test", "fix")


def is_release_prerelease(release: dict) -> bool:
    """Returns True if marked as pre-release in metadata or named like one."""
    if release.get("prerelease"):
        return True

    tag = release.get("tag_name", "").lower()
    name = (release.get("name") or "").lower()
    return any(kw in tag or kw in name for kw in PRE_RELEASE_KEYWORDS)


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

        # 1. Filter out draft releases
        valid_releases = [r for r in releases if not r.get("draft")]

        # 2. Sort by publication date descending (newest published first)
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
