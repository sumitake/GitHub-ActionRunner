#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Read-only byte consistency checks; never dispatch, admission, or upload approval."""
import argparse
import json
import pathlib
import sys

import _retained_qualification as retained


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'tooling', 'bundle', 'candidate', 'candidate-archive', 'expected-identities'):
        parser.add_argument('--' + name, required=True, type=pathlib.Path)
    args = parser.parse_args()
    identity = retained.read(args.expected_identities)
    result = retained.verify_bundle(args.source, args.tooling, args.bundle, args.candidate,
                                    identity, candidate_archive=args.candidate_archive)
    # Intentionally no ready/upload/admitted output. A supplied manifest cannot
    # confer controller-observed producer recognition or an owner decision.
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('qualification_inventory', 'identities')}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('retained qualification verification failed: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
