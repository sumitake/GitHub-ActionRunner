#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Recheck private prior evidence and emit its exact source-reviewed public receipt.

This does not build, execute, upload or sanitize by suppression. Original records
stay private and unchanged. The receipt cannot grant downstream qualification.
"""
import argparse
import pathlib

import _retained_runner as retained


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof-directory', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    data = retained.verify_private_evidence(retained.ROOT, args.proof_directory)
    if not args.output.is_absolute() or args.output.parent.resolve(strict=True) != args.output.parent:
        raise retained.q.Stop('canonical public receipt output required')
    with args.output.open('xb') as output:
        output.write(data)


if __name__ == '__main__':
    main()
