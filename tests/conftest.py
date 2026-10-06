"""Pytest configuration for cidr_subnet-pure (no fixtures needed)."""
import sys
import os
# Ensure src/ is importable without install
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)