#!/usr/bin/env python3
"""Validate SARIF files against a locally supplied, pinned OASIS schema.

This script performs no downloads. Obtain the schema using the documented
command in docs/TEST_MATRIX.md. Requires the optional requirements-qa.txt.
"""
import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft4Validator, FormatChecker


SCHEMA_URL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("reports", nargs="+", type=Path)
    args = parser.parse_args()
    raw = args.schema.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        parser.error("Schema does not match the pinned OASIS SARIF 2.1.0 Errata 01 schema")
    schema = json.loads(raw)
    Draft4Validator.check_schema(schema)
    validator = Draft4Validator(schema, format_checker=FormatChecker())
    for path in args.reports:
        value = json.loads(path.read_text(encoding="utf-8"))
        validator.validate(value)
        print("Valid SARIF: " + str(path))
    print("Schema SHA-256: " + SCHEMA_SHA256)


if __name__ == "__main__":
    main()
