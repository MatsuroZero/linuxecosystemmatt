#!/usr/bin/env python3
"""Install or roll back the NexusOne gateway in a legacy dashboard source file."""

from __future__ import annotations

import argparse
from pathlib import Path

from nexusone.dashboard_installer import (
    install_dashboard_gateway,
    restore_dashboard_backup,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dashboard-app",
        required=True,
        type=Path,
        help="Path to the existing System Dashboard app.py",
    )
    parser.add_argument(
        "--restore-backup",
        type=Path,
        help="Restore this backup instead of installing the gateway",
    )
    args = parser.parse_args()

    if args.restore_backup:
        recovery = restore_dashboard_backup(args.dashboard_app, args.restore_backup)
        print(f"Restored dashboard source. Previous source preserved at: {recovery}")
        return 0

    backup = install_dashboard_gateway(args.dashboard_app)
    print("NexusOne gateway integration inserted.")
    print(f"Original dashboard source preserved at: {backup}")
    print("The gateway defaults to loopback-only access. No service was restarted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
