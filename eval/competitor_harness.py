from __future__ import annotations

import sys

from ravage.__main__ import main

if __name__ == "__main__":
    main(["competitors", *sys.argv[1:]])
