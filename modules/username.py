import requests
import re

SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "X": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Medium": "https://medium.com/@{}",
    "Dev.to": "https://dev.to/{}",
    "HackerOne": "https://hackerone.com/{}",
    "Keybase": "https://keybase.io/{}",
}

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,39}$")


def analyze_username(username):
    if not USERNAME_RE.match(username):
        return {
            "type": "username",
            "target": username,
            "summary": "Invalid username format",
            "findings": [],
            "notice": "Usernames may only contain letters, numbers, underscores, dots, and hyphens.",
        }

    findings = []
    for name, url in SITES.items():
        try:
            r = requests.get(
                url.format(username),
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0 (KevinOSINT/2.0)"},
                allow_redirects=False,
            )
            exists = r.status_code in (200, 301, 302)
            findings.append({
                "label": name,
                "value": "Public page found" if exists else f"HTTP {r.status_code}",
                "status": "good" if exists else "info",
                "url": url.format(username),
            })
        except requests.RequestException:
            findings.append({"label": name, "value": "Check failed", "status": "warn"})

    return {
        "type": "username",
        "target": username,
        "summary": "Public username presence checks",
        "findings": findings,
        "notice": "A username match across sites is not proof that the accounts belong to the same person.",
    }
