#!/usr/bin/python3
"""Trusted Git HTTPS askpass for the protected bootstrap publisher job.

The token is supplied only through the reviewed job's environment secret.
This helper never reads the candidate tree or writes the credential to disk.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    prompt = sys.argv[1].lower() if len(sys.argv) == 2 else ""
    if prompt.startswith("username for 'https://github.com"):
        print("x-access-token")
        return 0
    if prompt.startswith("password for 'https://x-access-token@github.com"):
        token = os.environ.get("BOOTSTRAP_TARGET_PAT", "")
        if token.startswith("github_pat_") and token.isascii():
            print(token)
            return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
