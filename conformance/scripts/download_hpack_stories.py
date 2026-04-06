#!/usr/bin/env python3
"""Download hpack-test-case stories."""
import subprocess, os

DEST = os.path.join(os.path.dirname(__file__), "..", "vectors", "hpack-stories")


def main():
    if os.path.exists(DEST):
        print(f"Already exists: {DEST}")
        return
    subprocess.run(
        [
            "git",
            "clone",
            "--depth=1",
            "https://github.com/http2jp/hpack-test-case.git",
            DEST,
        ],
        check=True,
    )
    print(f"Downloaded to {DEST}")


if __name__ == "__main__":
    main()
