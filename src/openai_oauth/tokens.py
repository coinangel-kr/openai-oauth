"""Token storage, refresh, and validation for OpenAI OAuth."""

import base64
import hashlib
import json
import logging
import secrets
import threading
import time
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# --- Constants ---
ISSUER = "https://auth.openai.com"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
TOKEN_ENDPOINT = f"{ISSUER}/oauth/token"
SCOPES = "openid profile email offline_access"

DATA_DIR = Path.home() / ".openai-oauth"
TOKEN_FILE = DATA_DIR / "tokens.json"

_refresh_lock = threading.Lock()


# --- Token storage ---

def _save_tokens(data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.chmod(0o700)
    TOKEN_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    TOKEN_FILE.chmod(0o600)


def _load_tokens() -> dict | None:
    if not TOKEN_FILE.exists():
        return None
    try:
        return json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _decode_jwt_payload(token: str) -> dict:
    """Decode the payload of a JWT without verification (client-side use only)."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1]
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


# --- Token exchange: id_token -> OpenAI API key ---

def _exchange_for_api_key(id_token: str) -> str:
    """Exchange an id_token for a real OpenAI API key via token-exchange grant."""
    random_id = secrets.token_hex(6)
    params = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": CLIENT_ID,
        "requested_token": "openai-api-key",
        "subject_token": id_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "name": f"openai-oauth [auto-generated] ({time.strftime('%Y-%m-%d')}) [{random_id}]",
    }
    resp = httpx.post(
        TOKEN_ENDPOINT,
        data=params,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["access_token"]


# --- Refresh ---

def _refresh_tokens(refresh_token: str) -> dict:
    """Refresh tokens using the refresh_token grant."""
    resp = httpx.post(
        TOKEN_ENDPOINT,
        data={
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": SCOPES,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def _refresh_and_save() -> str:
    """Refresh the tokens and exchange for a new API key. Returns the API key."""
    stored = _load_tokens()
    if not stored or not stored.get("refresh_token"):
        raise RuntimeError("No refresh token found. Please run 'openai-oauth login'.")

    refreshed = _refresh_tokens(stored["refresh_token"])

    id_token = refreshed.get("id_token", stored.get("id_token", ""))
    new_refresh = refreshed.get("refresh_token", stored["refresh_token"])

    api_key = _exchange_for_api_key(id_token)

    claims = _decode_jwt_payload(id_token)
    expires = claims.get("exp", int(time.time()) + 3600)

    _save_tokens({
        "api_key": api_key,
        "id_token": id_token,
        "refresh_token": new_refresh,
        "expires": expires,
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    return api_key


# --- Public API ---

def is_authenticated() -> bool:
    """Check if valid tokens exist."""
    stored = _load_tokens()
    if not stored:
        return False
    return bool(stored.get("api_key") and stored.get("refresh_token"))


def get_api_key() -> str:
    """Get a valid OpenAI API key, refreshing if expired.

    Returns the API key string.
    Raises RuntimeError if not authenticated.
    Thread-safe: uses a lock to prevent concurrent refresh races.
    """
    with _refresh_lock:
        stored = _load_tokens()
        if not stored:
            raise RuntimeError("Not authenticated. Run 'openai-oauth login' first.")

        expires = stored.get("expires", 0)
        if time.time() >= expires - 300:
            logger.info("Token expired, refreshing...")
            return _refresh_and_save()

        api_key = stored.get("api_key", "")
        if not api_key:
            return _refresh_and_save()

        return api_key


def get_status() -> dict:
    """Return authentication status info."""
    stored = _load_tokens()
    if not stored:
        return {"authenticated": False}

    expires = stored.get("expires", 0)
    claims = _decode_jwt_payload(stored.get("id_token", ""))
    auth_info = claims.get("https://api.openai.com/auth", {})

    return {
        "authenticated": bool(stored.get("api_key")),
        "expires": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expires)),
        "expired": time.time() >= expires,
        "plan_type": auth_info.get("chatgpt_plan_type", "unknown"),
        "token_file": str(TOKEN_FILE),
    }


def logout() -> bool:
    """Securely remove stored tokens. Returns True if tokens were removed."""
    if TOKEN_FILE.exists():
        # Overwrite before deletion to prevent forensic recovery
        size = TOKEN_FILE.stat().st_size
        TOKEN_FILE.write_bytes(b"\x00" * size)
        TOKEN_FILE.unlink()
        return True
    return False
