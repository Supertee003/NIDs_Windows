#!/usr/bin/env python3
import json
needs = {
    "zig-build-test": {"result": "success"},
    "rust-pep-build": {"result": "success"},
    "c-native-build": {"result": "success"},
    "python-tests": {"result": "success"},
    "go-nose-build-test": {"result": "success"},
    "ts-policy-build": {"result": "success"},
    "security-scan": {"result": "success"},
    "ci-matrix": {"result": "success"},
    "go-aggregator-build-test": {"result": "success"},
    "cython-build-test": {"result": "success"},
    "shield": {"result": "success"},
}
res = json.dumps(needs)
print(res)