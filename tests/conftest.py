"""Shared pytest configuration and optional dependency stubs."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock


def _ensure_nemoguardrails_stub() -> None:
    if "nemoguardrails" in sys.modules:
        return
    mock_actions = MagicMock()
    mock_actions.action = lambda **kwargs: (lambda fn: fn)
    mock_pkg = MagicMock()
    mock_pkg.actions = mock_actions
    sys.modules["nemoguardrails"] = mock_pkg
    sys.modules["nemoguardrails.actions"] = mock_actions


_ensure_nemoguardrails_stub()
