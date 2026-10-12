"""Test bootstrap shared by local, CI, and legacy native update validation."""

import os


# Native updaters installed before v1.17.3 use this exact isolated-test token.
# Replace it only inside pytest so those installations can validate and adopt
# the stricter release without weakening the application's runtime policy.
if os.environ.get("SETTINGS_ADMIN_TOKEN") == "update-validation-only":
    os.environ["SETTINGS_ADMIN_TOKEN"] = "update-validation-only-0123456789abcdef"
