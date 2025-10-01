# cli/__main__.py
"""Entry point for CLI module when run as python -m cli"""

from cli.cli_scan import main
import sys

if __name__ == "__main__":
    sys.exit(main())