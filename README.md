# openai-oauth

Use your **ChatGPT Plus/Pro subscription** to get OpenAI API keys — no separate API billing needed.

This package implements the OAuth PKCE flow against OpenAI's auth server to exchange your ChatGPT subscription credentials for a real OpenAI API key.

## How It Works

```
You (browser)                    OpenAI Auth Server
     │                                  │
     │  1. Open auth URL (PKCE)         │
     │ ────────────────────────────────> │
     │                                  │
     │  2. Login with ChatGPT account   │
     │ <────────────────────────────────>│
     │                                  │
     │  3. Redirect with auth code      │
     │ <──────────────────────────────── │
     │                                  │
     │  4. Exchange code → tokens       │
     │ ────────────────────────────────> │
     │                                  │
     │  5. Exchange id_token → API key  │
     │ ────────────────────────────────> │
     │                                  │
     │  6. Done! API key saved locally  │
     ▼                                  ▼
```

Tokens are stored at `~/.openai-oauth/tokens.json` with `0600` permissions. The API key auto-refreshes when expired.

## Install

```bash
pip install openai-oauth
# or
uv add openai-oauth
```

For JWT signature verification (recommended for production):

```bash
pip install openai-oauth[crypto]
# or
uv add "openai-oauth[crypto]"
```

## CLI Usage

### Login (opens browser)

```bash
openai-oauth login
```

### Login (headless / SSH)

```bash
openai-oauth login --headless
```

### Login (server mode — for Docker)

```bash
openai-oauth login --server
```

### Check status

```bash
openai-oauth status
```

### Get API key (for scripts)

```bash
export OPENAI_API_KEY=$(openai-oauth key)
```

### Logout

```bash
openai-oauth logout
```

## Python API

```python
from openai_oauth import login, get_api_key, is_authenticated, get_status, logout

# Login (opens browser)
api_key = login()

# Check if authenticated
if is_authenticated():
    # Get a valid API key (auto-refreshes if expired)
    key = get_api_key()
    print(f"API key: {key[:8]}...")

# Check status
status = get_status()
print(f"Plan: {status['plan_type']}")
print(f"Expires: {status['expires']}")

# Logout
logout()
```

### Server mode (for Docker / bots)

```python
from openai_oauth import login_with_server

def on_success(plan_type):
    print(f"Logged in! Plan: {plan_type}")

auth_url = login_with_server(on_success=on_success)
print(f"Open this URL: {auth_url}")
# Server runs on port 1455, auto-completes when browser redirects back
```

## Configuration

Environment variables for customization:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_OAUTH_PORT` | `1455` | Callback server port |
| `OPENAI_OAUTH_CLIENT_ID` | *(built-in)* | Override the OAuth client ID |

## Security

- **PKCE** (RFC 7636): Prevents authorization code interception
- **State parameter**: CSRF protection with 256-bit random tokens
- **Token storage**: `~/.openai-oauth/tokens.json` with `0600` permissions
- **Secure logout**: Token file overwritten with zeros before deletion
- **JWT verification**: Signature verified against OpenAI's JWKS when `[crypto]` extra is installed
- **Localhost callback**: `http://localhost` redirect per RFC 8252 Section 7.3 (auth code never leaves the machine)
- **HTML escaping**: All dynamic content in callback HTML responses is escaped

## Requirements

- Python 3.11+
- A ChatGPT Plus or Pro subscription

## License

MIT
