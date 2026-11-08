"""Integrity checks for seed data files (pure file reads, no mocks)."""
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_advanced_payloads_have_required_fields():
    payloads = json.loads(_read("data/advanced_payloads.json"))
    assert payloads
    for p in payloads:
        assert p["test_name"]
        assert p["query"]


def test_security_payloads_have_required_fields():
    payloads = json.loads(_read("tests/security_payloads.json"))
    assert payloads
    for p in payloads:
        assert p["test_name"]
        assert p["query"]


def test_poisoned_policy_contains_expected_phishing_url():
    payloads = json.loads(_read("tests/security_payloads.json"))
    poisoned = _read("data/policy_poisoned.txt")
    for p in payloads:
        assert p["expected_phishing_url"] in poisoned
