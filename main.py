"""Main entry point for SXTOOL - react2shell."""
import sys
from pathlib import Path

# Ensure we can import from our modules
sys.path.insert(0, str(Path(__file__).parent))

from gui.window import run

if __name__ == "__main__":
    run()

