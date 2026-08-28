"""Shared test configuration."""

import os


os.environ.setdefault(
    "SESSION_SECRET", "test-session-secret-at-least-32-characters"
)
