"""Tests for Binary Inspector."""

import os

# Never ask GitHub for a newer release during the tests (update_check.py).
os.environ["BINARY_INSPECTOR_UPDATE_FEED_URL"] = "off"
