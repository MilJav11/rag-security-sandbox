"""Unit tests for app.output_guardrail (pure function, no mocks)."""
import pytest


def test_guardrail_allows_text_without_urls(app_module):
    assert app_module.output_guardrail("No links here at all.") is True


@pytest.mark.parametrize(
    "text",
    [
        "Reset your password at http://ourcompany.com/reset",
        "See https://ourcompany.com/policy or http://ourcompany.com/x",
    ],
)
def test_guardrail_allows_whitelisted_urls(app_module, text):
    assert app_module.output_guardrail(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "Go to http://evil-phishing.com/login now",
        "Clean http://ourcompany.com/x plus bad http://evil.com/y",
    ],
)
def test_guardrail_blocks_unlisted_urls(app_module, text):
    assert app_module.output_guardrail(text) is False


@pytest.mark.xfail(
    strict=True,
    reason="Known security gap: substring URL whitelist (http://ourcompany.com.evil.com/x passes)",
)
def test_guardrail_blocks_lookalike_domain(app_module):
    assert app_module.output_guardrail("http://ourcompany.com.evil.com/x") is False


@pytest.mark.xfail(
    strict=True,
    reason="Known security gap: regex URL scheme is case-sensitive (HTTP://EVIL.COM/x passes)",
)
def test_guardrail_blocks_uppercase_scheme(app_module):
    assert app_module.output_guardrail("HTTP://EVIL.COM/x") is False
