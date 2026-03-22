import random

from utils.colors import cyan, bold, magenta

_BANNER = """
  _____ _                        ____                     _
 |_   _| |__   ___ _ __ ___   ___/ ___|_   _  __ _ _ __ __| |
   | | | '_ \\ / _ \\ '_ ` _ \\ / _ \\ |  _| | | |/ _` | '__/ _` |
   | | | | | |  __/ | | | | |  __/ |_| | |_| | (_| | | | (_| |
   |_| |_| |_|\\___|_| |_| |_|\\___|\\____|\\__,_|\\__,_|_|  \\__,_|
"""

VERSION = "1.0.0"
AUTHOR = "Muhammad Abid (@V3n0mSh3ll)"

_TAGLINES = [
    "Nulled themes hide secrets. We find them.",
    "Trust no theme. Verify everything.",
    "Your last line of defense against backdoored themes.",
    "Scanning what others overlook.",
]

def print_banner():
    print(cyan(_BANNER))
    print(f"  {bold(magenta(random.choice(_TAGLINES)))}")
    print(f"  v{VERSION} | {AUTHOR}\n")
