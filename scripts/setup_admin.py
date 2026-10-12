#!/usr/bin/env python3
"""Create a per-installation admin access code without committing secrets."""

import argparse
import os
import re
import secrets
import stat
from pathlib import Path


TOKEN_NAME = "SETTINGS_ADMIN_TOKEN"


def setup_environment(project_root: Path) -> tuple[str, bool]:
    project_root = project_root.resolve()
    example_path = project_root / ".env.example"
    env_path = project_root / ".env"
    if not example_path.exists():
        raise FileNotFoundError(f"Missing environment template: {example_path}")

    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(env_path, flags)
    except FileNotFoundError:
        try:
            file_descriptor = os.open(env_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(file_descriptor, example_path.read_bytes())
            os.lseek(file_descriptor, 0, os.SEEK_SET)
        except FileExistsError:
            file_descriptor = os.open(env_path, flags)

    metadata = os.fstat(file_descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(file_descriptor)
        raise RuntimeError(".env must be a regular file, not a link or device")
    with os.fdopen(file_descriptor, "r+", encoding="utf-8") as handle:
        content = handle.read()
        match = re.search(rf"(?m)^{TOKEN_NAME}=(.*)$", content)
        current_value = match.group(1).strip() if match else ""
        if current_value:
            os.fchmod(handle.fileno(), 0o600)
            return current_value, False

        token = secrets.token_hex(24)
        if match:
            content = content[:match.start(1)] + token + content[match.end(1):]
        else:
            if content and not content.endswith("\n"):
                content += "\n"
            content += f"{TOKEN_NAME}={token}\n"
        handle.seek(0)
        handle.truncate()
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), 0o600)
        return token, True


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize Dark Threat Radar administrative access")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    token, generated = setup_environment(args.project_root)
    if generated:
        print("\nDark Threat Radar administrative access initialized.")
        print(f"Admin access code: {token}")
        print("Save this code in a password manager. It will not be shown by the web panel.\n")
    else:
        print("Administrative access is already configured in .env; the existing code was not displayed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
