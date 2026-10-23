#!/usr/bin/env python3
"""Offline source and workflow regressions; starts no build or container."""
# SPDX-License-Identifier: MPL-2.0
import os
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    os.chdir(ROOT)
    names = ('test_payload_reconstruction.py', 'test_bounded_qualification.py',
             'test_qualification_accounting.py', 'test_qualification_control.py',
             'test_workflow_policy.py', 'test_metadata_probe.py')
    suite = unittest.TestSuite(unittest.defaultTestLoader.discover('tests/repository', pattern=name) for name in names)
    return not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()


if __name__ == '__main__':
    raise SystemExit(main())
