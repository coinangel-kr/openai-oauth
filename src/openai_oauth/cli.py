"""CLI entry point for openai-oauth."""

import argparse
import sys
import time


def cmd_login(args):
    if args.headless:
        from .auth import login_headless
        login_headless()
    elif args.server:
        from .auth import CALLBACK_PORT, login_with_server
        timeout = 300
        auth_url = login_with_server(timeout=timeout)
        print(f"\nOpen this URL in a browser:\n\n{auth_url}\n")
        print(f"Waiting for callback on port {CALLBACK_PORT}...")
        print("Press Ctrl+C to cancel.\n")
        try:
            from .tokens import is_authenticated
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if is_authenticated():
                    break
                time.sleep(1)
            else:
                print("\nLogin timed out.")
                sys.exit(1)
        except KeyboardInterrupt:
            print("\nCancelled.")
            return
    else:
        from .auth import login
        login()

    from .tokens import get_status
    status = get_status()
    if status.get("authenticated"):
        print("\nLogin successful!")
        print(f"Plan: {status.get('plan_type', 'unknown')}")
        print(f"Expires: {status.get('expires', 'unknown')}")
        print(f"Token file: {status.get('token_file', 'unknown')}")


def cmd_status(_args):
    from .tokens import get_status
    status = get_status()

    if not status.get("authenticated"):
        print("Not authenticated. Run: openai-oauth login")
        sys.exit(1)

    print("Authenticated: yes")
    print(f"Plan: {status.get('plan_type', 'unknown')}")
    print(f"Expires: {status.get('expires', 'unknown')}")
    print(f"Expired: {'yes' if status.get('expired') else 'no'}")
    print(f"Token file: {status.get('token_file', 'unknown')}")


def cmd_logout(_args):
    from .tokens import logout
    if logout():
        print("Logged out. Tokens removed.")
    else:
        print("No tokens found.")


def cmd_key(_args):
    from .tokens import get_api_key
    try:
        api_key = get_api_key()
        print(api_key)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="openai-oauth",
        description="Authenticate with ChatGPT Plus/Pro to get OpenAI API keys via OAuth PKCE.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # login
    login_parser = subparsers.add_parser("login", help="Authenticate with OpenAI")
    login_group = login_parser.add_mutually_exclusive_group()
    login_group.add_argument(
        "--headless", action="store_true",
        help="Headless mode: print URL and paste callback manually",
    )
    login_group.add_argument(
        "--server", action="store_true",
        help="Server mode: start callback server (for Docker/remote). Port configurable via OPENAI_OAUTH_PORT",
    )
    login_parser.set_defaults(func=cmd_login)

    # status
    status_parser = subparsers.add_parser("status", help="Show authentication status")
    status_parser.set_defaults(func=cmd_status)

    # logout
    logout_parser = subparsers.add_parser("logout", help="Remove stored tokens")
    logout_parser.set_defaults(func=cmd_logout)

    # key
    key_parser = subparsers.add_parser(
        "key", help="Print the current API key (use with: export OPENAI_API_KEY=$(openai-oauth key))",
    )
    key_parser.set_defaults(func=cmd_key)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
