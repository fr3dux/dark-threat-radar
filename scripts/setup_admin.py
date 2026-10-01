#!/usr/bin/env python3
"""Create a per-installation admin access code without committing secrets."""

import argparse
import os
import re
import secrets
import shutil
from pathlib import Path


TOKEN_NAME = "SETTINGS_ADMIN_TOKEN"


def setup_environment(project_root: Path) -> tuple[str, bool]:
    project_root = project_root.resolve()
    example_path = project_root / ".env.example"
    env_path = project_root / ".env"
    if not example_path.exists():
        raise FileNotFoundError(f"Missing environment template: {example_path}")

    if not env_path.exists():
        shutil.copyfile(example_path, env_path)

    content = env_path.read_text(encoding="utf-8")
    match = re.search(rf"(?m)^{TOKEN_NAME}=(.*)$", content)
    current_value = match.group(1).strip() if match else ""
    if current_value:
        os.chmod(env_path, 0o600)
        return current_value, False

    token = secrets.token_hex(24)
    if match:
        content = content[:match.start(1)] + token + content[match.end(1):]
    else:
        if content and not content.endswith("\n"):
            content += "\n"
        content += f"{TOKEN_NAME}={token}\n"

    temp_path = env_path.with_name(".env.tmp")
    file_descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.chmod(temp_path, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp_path, env_path)
        os.chmod(env_path, 0o600)
    finally:
        if temp_path.exists():
            temp_path.unlink()
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
