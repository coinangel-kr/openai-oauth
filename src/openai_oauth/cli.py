"""CLI entry point for openai-oauth."""

import argparse
import sys


def cmd_login(args):
    if args.headless:
        from .auth import login_headless
        api_key = login_headless()
    elif args.server:
        from .auth import login_with_server
        auth_url = login_with_server()
        print(f"\nOpen this URL in a browser:\n\n{auth_url}\n")
        print("Waiting for callback on port 1455...")
        print("Press Ctrl+C to cancel.\n")
        try:
            import time
            while True:
                from .tokens import is_authenticated
                if is_authenticated():
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nCancelled.")
            return
        api_key = None
    else:
        from .auth import login
        api_key = login()

    if api_key:
        print(f"\nLogin successful! API key saved.")
    from .tokens import get_status
    status = get_status()
    if status.get("authenticated"):
        print(f"Plan: {status.get('plan_type', 'unknown')}")
        print(f"Expires: {status.get('expires', 'unknown')}")
        print(f"Token file: {status.get('token_file', 'unknown')}")


def cmd_status(args):
    from .tokens import get_status
    status = get_status()

    if not status.get("authenticated"):
        print("Not authenticated. Run: openai-oauth login")
        sys.exit(1)

    print(f"Authenticated: yes")
    print(f"Plan: {status.get('plan_type', 'unknown')}")
    print(f"Expires: {status.get('expires', 'unknown')}")
    print(f"Expired: {'yes' if status.get('expired') else 'no'}")
    print(f"Token file: {status.get('token_file', 'unknown')}")


def cmd_logout(args):
    from .tokens import logout
    if logout():
        print("Logged out. Tokens removed.")
    else:
        print("No tokens found.")


def cmd_key(args):
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
        help="Server mode: start callback server on port 1455 (for Docker/remote)",
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
