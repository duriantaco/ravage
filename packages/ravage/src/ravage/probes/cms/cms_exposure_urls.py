from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeSession
from ravage.probes.cms.cms_exposure_shared import _dedupe

_SEED_PATHS = (
    "/wp-content/backup-migration-config.php",
    "/wp-content/backup-migration-config.txt",
    "/wp-content/plugins/",
    "/wp-content/uploads/",
    "/wp-json/",
    "/wp-content/plugins/backup-backup/readme.txt",
    "/wp-content/plugins/backup-backup/background-errors.log",
    "/wp-content/plugins/backup-backup/includes/backup-heart.php",
    "/wp-content/plugins/backup-backup/includes/htaccess/default.json",
    "/?backup-migration=PROGRESS_LOGS&progress-id=latest.log&backup-id=current",
    "/?backup-migration=PROGRESS_LOGS&progress-id=latest_full.log&backup-id=current",
    "/?backup-migration=PROGRESS_LOGS&progress-id=latest_migration.log&backup-id=current",
    "/?backup-migration=PROGRESS_LOGS&progress-id=latest_migration_full.log&backup-id=current",
    "/?backup-migration=PROGRESS_LOGS&progress-id=latest_staging.log&backup-id=current",
    "/?backup-migration=PROGRESS_LOGS&progress-id=latest_staging_full.log&backup-id=current",
    "/wp-content/plugins/updraftplus/readme.txt",
    "/wp-content/plugins/duplicator/readme.txt",
    "/wp-content/plugins/backwpup/readme.txt",
    "/wordpress/wp-content/backup-migration-config.php",
    "/blog/wp-content/backup-migration-config.php",
)
_BACKUP_FILES = (
    "complete_logs.log",
    "background-errors.log",
    "backup.log",
    "restore.log",
    "backups/latest.log",
    "backups/latest_migration.log",
    "backups/md5summary.php",
    "backups/backup_manifest.json",
)
_BACKUP_HINT_RE = re.compile(r"(?:/wp-content/)?(backup-migration-[A-Za-z0-9_-]{4,})")
_ARTIFACT_RE = re.compile(
    r"([A-Za-z0-9_.-]+\.(?:zip|tar|tar\.gz|tgz|sql|sqlite|db|json|log|txt|php|xml|dat|wie|bak))",
    re.IGNORECASE,
)
_WP_PLUGIN_RE = re.compile(r"/wp-content/plugins/([A-Za-z0-9_.-]+)/")
_AUTO_INDEX_MARKERS = ("index of /", "[parentdir]", "parent directory")
_CMS_DIRECTORY_PREFIXES = ("/wp-content/uploads/", "/wp-content/plugins/", "/uploads/", "/files/")
_TEXT_ARTIFACT_SUFFIXES = (".xml", ".dat", ".wie", ".json", ".log", ".txt", ".sql", ".php", ".bak")
_STATIC_MEDIA_SUFFIXES = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".css",
    ".js",
)
_CMS_ENDPOINT_MARKERS = ("wp-content", "wp-json", "backup", "plugin")
_PLUGIN_PROBE_FILES = (
    "readme.txt",
    "changelog.txt",
    "background-errors.log",
    "debug.log",
    "includes/background-errors.log",
    "includes/backup-heart.php",
    "includes/htaccess/default.json",
)
_BACKUP_BACKUP_PROBE_FILES = (
    "readme.txt",
    "background-errors.log",
    "includes/background-errors.log",
    "includes/backup-heart.php",
    "includes/htaccess/default.json",
)


def _initial_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    urls.extend(_seed_urls(session))
    urls.extend(_backup_hint_urls(session, _signal_text(state)))
    urls.extend(_signal_endpoint_urls(session, state))
    return _dedupe(urls)[:24]


def _derived_urls(session: ProbeSession, current_url: str, body: str) -> list[str]:
    urls: list[str] = []
    urls.extend(_current_plugin_urls(session, current_url))
    urls.extend(_backup_backup_plugin_urls(session, body))
    urls.extend(_backup_hint_urls(session, body))
    urls.extend(_artifact_urls(current_url, body))
    urls.extend(_href_urls(current_url, body))
    return _in_scope_unique_urls(session, urls)[:24]


def _seed_urls(session: ProbeSession) -> list[str]:
    urls: list[str] = []
    for path in _SEED_PATHS:
        urls.append(session.absolute(path))
    return urls


def _signal_text(state: AgentState) -> str:
    parts: list[str] = []
    for values in state.signals.values():
        for value in values[-20:]:
            parts.append(str(value))
    return " ".join(parts)


def _signal_endpoint_urls(session: ProbeSession, state: AgentState) -> list[str]:
    urls: list[str] = []
    for endpoint in state.signals.get("endpoints", []):
        raw = str(endpoint)
        if _looks_cms_signal_endpoint(raw):
            urls.append(session.absolute(raw))
    return urls


def _looks_cms_signal_endpoint(value: str) -> bool:
    lowered = value.lower()
    for marker in _CMS_ENDPOINT_MARKERS:
        if marker in lowered:
            return True
    return False


def _current_plugin_urls(session: ProbeSession, current_url: str) -> list[str]:
    urls: list[str] = []
    plugin_match = _WP_PLUGIN_RE.search(current_url)
    if not plugin_match:
        return urls

    plugin_name = plugin_match.group(1).strip("/")
    plugin_base = session.absolute("/wp-content/plugins/" + plugin_name + "/")
    urls.extend(_plugin_file_urls(plugin_base, _PLUGIN_PROBE_FILES))
    return urls


def _backup_backup_plugin_urls(session: ProbeSession, body: str) -> list[str]:
    if not _body_mentions_backup_backup_plugin(body):
        return []
    plugin_base = session.absolute("/wp-content/plugins/backup-backup/")
    return _plugin_file_urls(plugin_base, _BACKUP_BACKUP_PROBE_FILES)


def _body_mentions_backup_backup_plugin(body: str) -> bool:
    lowered = body.lower()
    markers = ("backup migration", "backupbliss", "backup-backup")
    for marker in markers:
        if marker in lowered:
            return True
    return False


def _plugin_file_urls(plugin_base: str, filenames: tuple[str, ...]) -> list[str]:
    urls: list[str] = []
    for name in filenames:
        urls.append(urljoin(plugin_base, name))
    return urls


def _backup_hint_urls(session: ProbeSession, text: str) -> list[str]:
    urls: list[str] = []
    for match in _BACKUP_HINT_RE.finditer(text):
        base = session.absolute("/wp-content/" + match.group(1).strip("/") + "/")
        urls.append(base)
        urls.extend(_backup_file_urls(base))
    return urls


def _backup_file_urls(base_url: str) -> list[str]:
    urls: list[str] = []
    for name in _BACKUP_FILES:
        urls.append(urljoin(base_url, name))
    return urls


def _artifact_urls(current_url: str, body: str) -> list[str]:
    urls: list[str] = []
    base = _containing_url(current_url)
    for match in _ARTIFACT_RE.finditer(body):
        name = match.group(1).strip("'\"")
        if name.lower() in {"index.php"}:
            continue
        urls.append(urljoin(base, name))
        if _looks_backup_config_url(current_url) and "/backups/" not in base:
            urls.append(urljoin(base.rstrip("/") + "/backups/", name))
    return urls


def _href_urls(current_url: str, body: str) -> list[str]:
    urls: list[str] = []
    base = _containing_url(current_url)
    for href in re.findall(r"""(?is)\b(?:href|src)\s*=\s*['"]([^'"]+)['"]""", body):
        if _interesting_cms_href(current_url, href, body):
            urls.append(urljoin(base, href))
    return urls


def _in_scope_unique_urls(session: ProbeSession, urls: list[str]) -> list[str]:
    in_scope: list[str] = []
    for url in urls:
        if session.in_scope(url):
            in_scope.append(url)
    return _dedupe(in_scope)


def _interesting_cms_href(current_url: str, href: str, body: str) -> bool:
    lowered = href.lower().strip()
    if not lowered or lowered.startswith(("#", "mailto:", "tel:", "javascript:")):
        return False
    if lowered.startswith("?") or lowered in {"../", "./"}:
        return False
    if "parent directory" in lowered:
        return False
    if _href_has_artifact_marker(lowered):
        return True
    if lowered.endswith(_TEXT_ARTIFACT_SUFFIXES):
        return True
    if lowered.endswith("/") and _looks_cms_directory_listing(current_url, body):
        return not lowered.startswith("/")
    if lowered.endswith(_STATIC_MEDIA_SUFFIXES):
        return False
    return False


def _href_has_artifact_marker(lowered_href: str) -> bool:
    markers = ("backup", "wp-content", ".zip", ".tar", ".tgz", ".sql", ".log", ".json")
    for marker in markers:
        if marker in lowered_href:
            return True
    return False


def _looks_cms_directory_listing(current_url: str, body: str) -> bool:
    path = urlsplit(current_url).path.lower()
    if not _path_has_cms_directory_prefix(path):
        return False
    lowered = body[:5000].lower()
    return _body_has_auto_index_marker(lowered)


def _path_has_cms_directory_prefix(path: str) -> bool:
    for prefix in _CMS_DIRECTORY_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def _body_has_auto_index_marker(lowered_body: str) -> bool:
    for marker in _AUTO_INDEX_MARKERS:
        if marker in lowered_body:
            return True
    return False


def _containing_url(url: str) -> str:
    clean = url.split("?", 1)[0]
    if clean.endswith("/"):
        return clean
    return clean.rsplit("/", 1)[0] + "/"


def _looks_backup_config_url(url: str) -> bool:
    lowered = url.lower()
    if "backup-migration-" not in lowered:
        return False
    markers = ("/backups/", "complete_logs", "latest")
    for marker in markers:
        if marker in lowered:
            return True
    return False
