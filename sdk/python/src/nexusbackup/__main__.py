"""`python3 -m nexusbackup fingerprint https://host:8443`: the SHA-256 fingerprint of the certificate an appliance
presents, unchecked. Compare it with the one the appliance shows (Settings -> Certificate) before pinning it."""

from __future__ import annotations

import sys

from ._transport import get_server_fingerprint


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "fingerprint":
        print(__doc__, file=sys.stderr)
        return 2
    print(get_server_fingerprint(argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
