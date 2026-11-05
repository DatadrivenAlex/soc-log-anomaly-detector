"""Session fixtures."""

from __future__ import annotations

import pytest

from socdetect.engine import Rule, load_rules


@pytest.fixture(scope="session")
def rules() -> list[Rule]:
    return load_rules()
