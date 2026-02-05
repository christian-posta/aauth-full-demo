#!/usr/bin/env python3
"""
Entry point for running the backend with 'uv run .'
This file allows the current directory to be executed as a Python package.

CLI options (must be parsed before app imports):
  --signature-scheme {hwk,jwks}  Override AAUTH_SIGNATURE_SCHEME (default: env or hwk)

Example:
  uv run . --signature-scheme jwks
"""
import argparse
import os

# Parse CLI args before any app imports (services read AAUTH_SIGNATURE_SCHEME at import time)
parser = argparse.ArgumentParser(description="Supply Chain Backend")
parser.add_argument(
    "--signature-scheme",
    choices=["hwk", "jwks"],
    help="AAuth signature scheme (overrides AAUTH_SIGNATURE_SCHEME env; default: hwk)",
)
args, _ = parser.parse_known_args()

if args.signature_scheme:
    os.environ["AAUTH_SIGNATURE_SCHEME"] = args.signature_scheme

from app.main import main

if __name__ == "__main__":
    main()
