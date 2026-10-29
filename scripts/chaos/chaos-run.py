#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Retired production burst runner. This entry point never makes network calls."""
import sys


def main():
    print("RETIRED: this runner encoded obsolete session revival and permissive failure budgets.")
    print("Use chaos-fix-regression.py for bounded owner-verified acceptance, or")
    print("chaos-test-clients.py for explicitly authorized client/burst probes.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
