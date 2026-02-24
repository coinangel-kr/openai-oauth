"""OAuth PKCE authentication flow for OpenAI."""

import hashlib
import base64
import logging
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from .tokens import (
    CLIENT_ID,
    SCOPES,
    TOKEN_ENDPOINT,
    _decode_jwt_payload,
    _exchange_for_api_key,
    _save_tokens,
)

logger = logging.getLogger(__name__)

AUTH_ENDPOINT = "https://auth.openai.com/oauth/authorize"
CALLBACK_PORT = 1455
REDIRECT_URI = f"http://localhost:{CALLBACK_PORT}/auth/callback"


# --- PKCE ---

def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = secrets.token_hex(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _build_auth_url(challenge: str, state: str) -> str:
    """Build the OAuth authorization URL."""
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "state": state,
    }
    return f"{AUTH_ENDPOINT}?{urlencode(params)}"


def _complete_login(code: str, verifier: str) -> str:
    """Exchange authorization code for tokens and API key. Returns the API key."""
    resp = httpx.post(
        TOKEN_ENDPOINT,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    token_data = resp.json()

    id_token = token_data.get("id_token")
    refresh_token = token_data.get("refresh_token")
    if not id_token or not refresh_token:
        raise RuntimeError(
            f"Token response missing required fields. Got keys: {list(token_data.keys())}"
        )

    api_key = _exchange_for_api_key(id_token)

    claims = _decode_jwt_payload(id_token)
    expires = claims.get("exp", int(time.time()) + 3600)

    _save_tokens({
        "api_key": api_key,
        "id_token": id_token,
        "refresh_token": refresh_token,
        "expires": expires,
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    return api_key


# --- Login flows ---

def login() -> str:
    """Run OAuth PKCE login with a local browser.

    Opens the browser for authentication and starts a local HTTP server
    to receive the callback. Returns the obtained OpenAI API key.
    """
    verifier, challenge = _generate_pkce()
    state = secrets.token_hex(32)
    auth_url = _build_auth_url(challenge, state)

    received_code = None
    done_event = Event()

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal received_code
            parsed = urlparse(self.path)

            if parsed.path == "/auth/callback":
                params = parse_qs(parsed.query)
                cb_state = params.get("state", [None])[0]
                code = params.get("code", [None])[0]

                if cb_state != state:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Invalid state")
                    return

                received_code = code
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h2>Login successful!</h2>"
                    b"<p>You can close this window.</p></body></html>"
                )
                done_event.set()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", CALLBACK_PORT), CallbackHandler)
    server.timeout = 120

    logger.info("Opening browser for OpenAI login...")
    webbrowser.open(auth_url)

    deadline = time.time() + 120
    while not done_event.is_set():
        if time.time() > deadline:
            server.server_close()
            raise RuntimeError("Login timed out (120s). Browser did not complete OAuth flow.")
        server.handle_request()

    server.server_close()

    if not received_code:
        raise RuntimeError("No authorization code received.")

    return _complete_login(received_code, verifier)


def login_headless() -> str:
    """Run OAuth PKCE login in headless mode.

    Prints the auth URL for the user to open manually,
    then waits for the user to paste the callback URL.
    Returns the obtained OpenAI API key.
    """
    verifier, challenge = _generate_pkce()
    state = secrets.token_hex(32)
    auth_url = _build_auth_url(challenge, state)

    print(f"\nOpen this URL in a browser:\n\n{auth_url}\n")
    print("After login, paste the full callback URL here:")
    callback_url = input("> ").strip()

    parsed = urlparse(callback_url)
    params = parse_qs(parsed.query)
    code = params.get("code", [None])[0]
    cb_state = params.get("state", [None])[0]

    if cb_state != state:
        raise RuntimeError("State mismatch — possible CSRF attack.")
    if not code:
        raise RuntimeError("No authorization code in the pasted URL.")

    return _complete_login(code, verifier)


def login_with_server(on_success=None, timeout: int = 300) -> str:
    """Start OAuth login with an automatic callback server.

    Runs an HTTP server on port 1455 in a background thread to receive
    the OAuth callback automatically. Useful for Docker or server environments.

    Args:
        on_success: Optional callback(plan_type: str) called on successful login.
        timeout: Server timeout in seconds (default 300s / 5 min).

    Returns:
        The auth URL to open in a browser.
    """
    verifier, challenge = _generate_pkce()
    state = secrets.token_hex(32)
    auth_url = _build_auth_url(challenge, state)

    done = Event()

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path != "/auth/callback":
                self.send_response(404)
                self.end_headers()
                return

            params_qs = parse_qs(parsed.query)
            code = params_qs.get("code", [None])[0]
            cb_state = params_qs.get("state", [None])[0]

            if cb_state != state or not code:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid request")
                done.set()
                return

            try:
                _complete_login(code, verifier)
                from .tokens import get_status
                status = get_status()
                plan_type = status.get("plan_type", "unknown")

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    f"<html><body><h2>Login successful!</h2>"
                    f"<p>Plan: {plan_type}</p>"
                    f"<p>You can close this window.</p></body></html>".encode()
                )

                if on_success:
                    try:
                        on_success(plan_type)
                    except Exception:
                        logger.exception("on_success callback failed")

            except Exception as e:
                logger.exception("Auto-callback login failed")
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    f"<html><body><h2>Login failed</h2>"
                    f"<p>{e}</p></body></html>".encode()
                )

            done.set()

        def log_message(self, format, *args):
            pass

    try:
        server = HTTPServer(("0.0.0.0", CALLBACK_PORT), CallbackHandler)
    except OSError:
        logger.warning("Port %d busy, returning auth URL for manual flow", CALLBACK_PORT)
        return auth_url

    server.timeout = 1

    def serve():
        deadline = time.time() + timeout
        while not done.is_set() and time.time() < deadline:
            server.handle_request()
        server.server_close()

    threading.Thread(target=serve, daemon=True).start()
    return auth_url
