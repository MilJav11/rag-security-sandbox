"""Proof that the network guard actually blocks real connection attempts."""
import pytest
import requests

from conftest import NetworkBlocked


def test_network_guard_blocks_real_call():
    with pytest.raises(NetworkBlocked):
        requests.get("http://example.com", timeout=5)
