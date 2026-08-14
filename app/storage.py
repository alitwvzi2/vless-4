import hashlib
import json
import os
import threading
import time
import uuid as uuid_lib
from datetime import datetime, timedelta, timezone

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DATA_FILE = os.path.join(DATA_DIR, "users.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

DEFAULT_GROUP = "عمومی"

DEFAULT_CONFIG = {
    "port": 443,
    "security": "tls",       # tls | none
    "alpn": "h2,http/1.1",   # h2,http/1.1 | h2 | http/1.1
    "fingerprint": "chrome", # chrome | firefox | safari | ios | android | edge | random | randomized
    "ws_path": os.environ.get("WSPATH", "/tun"),  # only used to seed the very first run
    "sni": "",               # empty = use the public domain
}

_lock = threading.Lock()
_users: dict[str, dict] = {}
_settings: dict = {}

START_TIME = time.monotonic()

# in-memory (not persisted) count of live websocket connections per uuid
_active: dict[str, int] = {}
_active_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------
def load() -> None:
    global _users, _settings
    with _lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r") as f:
                    _users = json.load(f)
            except Exception:
                _users = {}
        else:
            _users = {}

        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f:
                    _settings = json.load(f)
            except Exception:
                _settings = {}
        else:
            _settings = {}

    # backfill any missing fields on old records so upgrades don't crash
    changed = False
    with _lock:
        for u in _users.values():
            for key, default in (
                ("note", ""),
                ("expires_at", None),
                ("data_limit_mb", 0),
                ("bytes_up", 0),
                ("bytes_down", 0),
                ("group", DEFAULT_GROUP),
            ):
                if key not in u:
                    u[key] = default
                    changed = True
    if changed:
        save()

    # backfill default config / groups on the settings side too
    settings_changed = False
    with _lock:
        if "config" not in _settings:
            _settings["config"] = dict(DEFAULT_CONFIG)
            settings_changed = True
        else:
            for k, v in DEFAULT_CONFIG.items():
                if k not in _settings["config"]:
                    _settings["config"][k] = v
                    settings_changed = True
        if "groups" not in _settings:
            _settings["groups"] = [DEFAULT_GROUP]
            settings_changed = True
        elif DEFAULT_GROUP not in _settings["groups"]:
            _settings["groups"].insert(0, DEFAULT_GROUP)
            settings_changed = True
    if settings_changed:
        _save_settings()


def save() -> None:
    with _lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_users, f, indent=2)
        os.replace(tmp, DATA_FILE)


def _save_settings() -> None:
    with _lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = SETTINGS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_settings, f, indent=2)
        os.replace(tmp, SETTINGS_FILE)


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------
def list_users() -> list[dict]:
    with _lock:
        return [dict(u, uuid=k) for k, u in _users.items()]


def get_user(user_uuid: str) -> dict | None:
    with _lock:
        u = _users.get(user_uuid)
        return dict(u, uuid=user_uuid) if u else None


def add_user(
    name: str,
    note: str = "",
    expires_in_days: int = 0,
    data_limit_mb: int = 0,
    group: str = "",
) -> str:
    new_uuid = str(uuid_lib.uuid4())
    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = (_now_dt() + timedelta(days=expires_in_days)).isoformat()
    group_name = (group or DEFAULT_GROUP).strip() or DEFAULT_GROUP
    with _lock:
        _users[new_uuid] = {
            "name": name or "user",
            "note": note or "",
            "enabled": True,
            "created_at": _now(),
            "expires_at": expires_at,
            "data_limit_mb": max(0, data_limit_mb or 0),
            "bytes_up": 0,
            "bytes_down": 0,
            "group": group_name,
        }
        if group_name not in _settings.get("groups", []):
            _settings.setdefault("groups", []).append(group_name)
    save()
    _save_settings()
    return new_uuid


def edit_user(
    user_uuid: str,
    name: str | None = None,
    note: str | None = None,
    expires_in_days: int | None = None,
    data_limit_mb: int | None = None,
    group: str | None = None,
) -> None:
    with _lock:
        u = _users.get(user_uuid)
        if not u:
            return
        if name is not None:
            u["name"] = name or u["name"]
        if note is not None:
            u["note"] = note
        if expires_in_days is not None:
            if expires_in_days <= 0:
                u["expires_at"] = None
            else:
                u["expires_at"] = (_now_dt() + timedelta(days=expires_in_days)).isoformat()
        if data_limit_mb is not None:
            u["data_limit_mb"] = max(0, data_limit_mb)
        if group:
            group_name = group.strip() or DEFAULT_GROUP
            u["group"] = group_name
            if group_name not in _settings.get("groups", []):
                _settings.setdefault("groups", []).append(group_name)
    save()
    _save_settings()


def delete_user(user_uuid: str) -> None:
    with _lock:
        _users.pop(user_uuid, None)
    save()


def toggle_user(user_uuid: str) -> None:
    with _lock:
        if user_uuid in _users:
            _users[user_uuid]["enabled"] = not _users[user_uuid]["enabled"]
    save()


def reset_traffic(user_uuid: str) -> None:
    with _lock:
        u = _users.get(user_uuid)
        if u:
            u["bytes_up"] = 0
            u["bytes_down"] = 0
    save()


def reset_all_traffic() -> None:
    with _lock:
        for u in _users.values():
            u["bytes_up"] = 0
            u["bytes_down"] = 0
    save()


def regenerate_uuid(old_uuid: str) -> str | None:
    """Rotate a user's connection UUID, keeping name/history, invalidating old configs."""
    with _lock:
        u = _users.pop(old_uuid, None)
        if not u:
            return None
        new_uuid = str(uuid_lib.uuid4())
        _users[new_uuid] = u
    save()
    return new_uuid


def user_status(u: dict) -> str:
    """Returns 'active' | 'disabled' | 'expired' | 'quota_exceeded'."""
    if not u.get("enabled", True):
        return "disabled"
    expires_at = u.get("expires_at")
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at) <= _now_dt():
                return "expired"
        except Exception:
            pass
    limit_mb = u.get("data_limit_mb", 0)
    if limit_mb:
        used_mb = (u.get("bytes_up", 0) + u.get("bytes_down", 0)) / (1024 * 1024)
        if used_mb >= limit_mb:
            return "quota_exceeded"
    return "active"


def is_user_enabled(user_uuid: str) -> bool:
    with _lock:
        u = _users.get(user_uuid)
        if not u:
            return False
        u = dict(u)
    return user_status(u) == "active"


def record_traffic(user_uuid: str, up: int, down: int) -> None:
    with _lock:
        u = _users.get(user_uuid)
        if not u:
            return
        u["bytes_up"] = u.get("bytes_up", 0) + up
        u["bytes_down"] = u.get("bytes_down", 0) + down
    # Caller throttles flush-to-disk frequency; save() is called separately.


# ---------------------------------------------------------------------------
# live connection tracking (in-memory only, resets on restart)
# ---------------------------------------------------------------------------
def connection_opened(user_uuid: str) -> None:
    with _active_lock:
        _active[user_uuid] = _active.get(user_uuid, 0) + 1


def connection_closed(user_uuid: str) -> None:
    with _active_lock:
        if user_uuid in _active:
            _active[user_uuid] -= 1
            if _active[user_uuid] <= 0:
                del _active[user_uuid]


def active_connection_count() -> int:
    with _active_lock:
        return sum(_active.values())


def is_active_now(user_uuid: str) -> bool:
    with _active_lock:
        return _active.get(user_uuid, 0) > 0


def uptime_seconds() -> float:
    return time.monotonic() - START_TIME


# ---------------------------------------------------------------------------
# admin password (overridable at runtime, persisted to settings.json)
# ---------------------------------------------------------------------------
def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def set_admin_password(new_password: str) -> None:
    salt = uuid_lib.uuid4().hex
    with _lock:
        _settings["admin_password_salt"] = salt
        _settings["admin_password_hash"] = _hash_password(new_password, salt)
    _save_settings()


def verify_admin_password(password: str, env_default: str) -> bool:
    with _lock:
        salt = _settings.get("admin_password_salt")
        stored_hash = _settings.get("admin_password_hash")
    if salt and stored_hash:
        return _hash_password(password, salt) == stored_hash
    return password == env_default


def has_custom_password() -> bool:
    with _lock:
        return bool(_settings.get("admin_password_hash"))


# ---------------------------------------------------------------------------
# groups (for organizing users into categories, e.g. "VIP" / "تست" / "عمومی")
# ---------------------------------------------------------------------------
def list_groups() -> list[str]:
    with _lock:
        groups = list(_settings.get("groups", [DEFAULT_GROUP]))
    # make sure every group actually used by a user shows up too, even if
    # it somehow isn't in the explicit list (defensive, shouldn't normally happen)
    with _lock:
        used = {u.get("group", DEFAULT_GROUP) for u in _users.values()}
    for g in used:
        if g not in groups:
            groups.append(g)
    return groups


def add_group(name: str) -> None:
    name = (name or "").strip()
    if not name:
        return
    with _lock:
        if name not in _settings.setdefault("groups", [DEFAULT_GROUP]):
            _settings["groups"].append(name)
    _save_settings()


def delete_group(name: str) -> None:
    if name == DEFAULT_GROUP:
        return  # the default group can't be removed
    with _lock:
        groups = _settings.get("groups", [])
        if name in groups:
            groups.remove(name)
        # reassign any users in the deleted group back to the default group
        for u in _users.values():
            if u.get("group") == name:
                u["group"] = DEFAULT_GROUP
    save()
    _save_settings()


def group_counts() -> dict[str, int]:
    """Number of users per group name."""
    counts: dict[str, int] = {}
    with _lock:
        for u in _users.values():
            g = u.get("group", DEFAULT_GROUP)
            counts[g] = counts.get(g, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# global VLESS link configuration (port / security / alpn / fingerprint / ws path)
# ---------------------------------------------------------------------------
def get_config() -> dict:
    with _lock:
        cfg = dict(DEFAULT_CONFIG)
        cfg.update(_settings.get("config", {}))
        return cfg


def update_config(**kwargs) -> None:
    with _lock:
        cfg = _settings.setdefault("config", dict(DEFAULT_CONFIG))
        for k, v in kwargs.items():
            if k in DEFAULT_CONFIG and v is not None:
                cfg[k] = v
    _save_settings()


load()
