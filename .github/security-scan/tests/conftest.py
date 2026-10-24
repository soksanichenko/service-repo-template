"""Make the security_scan package importable without installing it."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
