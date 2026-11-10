import os
from pathlib import Path
import sys
import time

name = sys.argv[1]
path = Path(f"/tmp/{name}.heartbeat" if os.name == "posix" else f".work/{name}.heartbeat")
sys.exit(0 if path.exists() and time.time() - float(path.read_text()) < 45 else 1)
