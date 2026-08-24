"""Bootstrap a GAnet host bridge under an explicitly selected Python."""
from __future__ import annotations

import sys
from pathlib import Path

_package_root = Path(__file__).resolve().parent.parent
if str(_package_root) not in sys.path:
    sys.path.insert(0, str(_package_root))

from ganet.device_access.bridge import main


if __name__ == "__main__":
    raise SystemExit(main())
