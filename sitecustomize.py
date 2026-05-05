"""Project-local interpreter defaults for reliable test runs.

This file is loaded by Python before ``python -m pytest``.  It disables unrelated
third-party pytest plugin autoloading so the release test command is deterministic
on developer machines and CI images that have extra global plugins installed.
It does not affect normal application startup.
"""
from __future__ import annotations

import os
import sys

if any(arg.endswith('pytest') or arg == 'pytest' or 'pytest' in arg for arg in sys.argv):
    os.environ.setdefault('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')
