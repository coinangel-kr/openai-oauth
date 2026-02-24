"""OAuth PKCE authentication flow for OpenAI."""

import base64
import hashlib
import logging
import os
import secrets
import threading
import time
import webbrowser
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event
from urllib.parse import parse_qs, urlencode, urlparse

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


def _parse_port() -> int:
    raw = os.environ.get("OPENAI_OAUTH_PORT", "1455")
    try:
        port = int(raw)
    except ValueError:
        raise ValueError(f"OPENAI_OAUTH_PORT must be an integer, got: {raw!r}") from None
    if not (1 <= port <= 65535):
        raise ValueError(f"OPENAI_OAUTH_PORT must be 1-65535, got: {port}")
    return port


CALLBACK_PORT = _parse_port()

# http://localhost is permitted for native OAuth apps per RFC 8252 Section 7.3.
# The authorization code never leaves the local machine.
REDIRECT_URI = f"http://localhost:{CALLBACK_PORT}/auth/callback"

_LOCALHOST_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]"})


def _is_localhost_host(host_header: str) -> bool:
    """Return True if the Host header value refers to a loopback address.

    Extracts the hostname (stripping port), normalizes case, and checks
    against an exact allowlist to prevent DNS rebinding attacks where
    an attacker-controlled domain like ``localhost.evil.com`` resolves to
    127.0.0.1.
    """
    host = host_header.strip()
    if host.startswith("["):
        # IPv6 bracket notation: [::1] or [::1]:port
        bracket_end = host.find("]")
        hostname = host[: bracket_end + 1] if bracket_end != -1 else host
    elif ":" in host:
        # hostname:port — strip port
        hostname = host.rsplit(":", 1)[0]
    else:
        hostname = host
    return hostname.lower() in _LOCALHOST_HOSTS


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


def _prepare_auth_session() -> tuple[str, str, str]:
    """Generate PKCE + state and return (verifier, state, auth_url)."""
    verifier, challenge = _generate_pkce()
    state = secrets.token_hex(32)
    return verifier, state, _build_auth_url(challenge, state)


def _complete_login(code: str, verifier: str) -> str:
    """Exchange authorization code for tokens and API key. Returns the API key."""
    import httpx

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
            "Token response missing required fields (id_token or refresh_token)."
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
    verifier, state, auth_url = _prepare_auth_session()

    received_code = None
    done_event = Event()

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal received_code

            # DNS rebinding defense: reject requests from non-loopback Host
            if not _is_localhost_host(self.headers.get("Host", "")):
                self.send_response(403)
                self.end_headers()
                return

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
    verifier, state, auth_url = _prepare_auth_session()

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


def login_with_server(
    on_success=None,
    timeout: int = 300,
    bind_address: str = "127.0.0.1",
) -> str:
    """Start OAuth login with an automatic callback server.

    Runs an HTTP server in a background thread to receive the OAuth
    callback automatically. Useful for Docker or server environments.

    Args:
        on_success: Optional callback(plan_type: str) called on successful login.
        timeout: Server timeout in seconds (default 300s / 5 min).
        bind_address: Address to bind the callback server to.
            Use "127.0.0.1" (default) for local-only access.
            Use "0.0.0.0" for Docker or remote environments where the
            callback needs to be accessible from outside the container.

    Returns:
        The auth URL to open in a browser.

    Raises:
        RuntimeError: If the callback port is already in use.
    """
    verifier, state, auth_url = _prepare_auth_session()

    done = Event()

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # DNS rebinding defense: reject requests from non-loopback Host
            # Skip when bound to 0.0.0.0 (Docker) where Host will be external
            if bind_address in ("127.0.0.1", "::1"):
                if not _is_localhost_host(self.headers.get("Host", "")):
                    self.send_response(403)
                    self.end_headers()
                    return

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
                return  # Keep listening — don't stop server on invalid requests

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
                    f"<p>Plan: {escape(str(plan_type))}</p>"
                    f"<p>You can close this window.</p></body></html>".encode()
                )

                if on_success:
                    try:
                        on_success(plan_type)
                    except Exception:
                        logger.error("on_success callback failed")

            except Exception as e:
                logger.error("Auto-callback login failed: %s", type(e).__name__)
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h2>Login failed</h2>"
                    b"<p>Authentication error. Check the terminal for details.</p></body></html>"
                )

            done.set()

        def log_message(self, format, *args):
            pass

    try:
        server = HTTPServer((bind_address, CALLBACK_PORT), CallbackHandler)
    except OSError as e:
        raise RuntimeError(
            f"Port {CALLBACK_PORT} is already in use. "
            "Set OPENAI_OAUTH_PORT to a free port."
        ) from e

    server.timeout = 1

    def serve():
        deadline = time.time() + timeout
        while not done.is_set() and time.time() < deadline:
            server.handle_request()
        server.server_close()

    threading.Thread(target=serve, daemon=True).start()
    return auth_url
