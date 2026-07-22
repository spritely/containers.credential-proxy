import re

import pytest
from mitmproxy.test import taddons, tflow, tutils

import injector


def _flow(host, headers):
    flow = tflow.tflow(req=tutils.treq(host=host, port=443))
    for name, value in headers.items():
        flow.request.headers[name] = value
    return flow


@pytest.fixture(autouse=True)
def _reset_injector_state(monkeypatch):
    monkeypatch.setattr(injector, "SECRETS", {})
    monkeypatch.setattr(injector, "ALLOWED_SECRETS", {})


class TestLoadSecrets:
    def test_missing_dir_returns_empty(self, tmp_path):
        assert injector._load_secrets(tmp_path / "does-not-exist") == {}

    def test_reads_and_strips_files(self, tmp_path):
        (tmp_path / "GITHUB_TOKEN").write_text("ghp_abc123\n")
        (tmp_path / "ANTHROPIC_API_KEY").write_text("  sk-ant-xyz  ")
        assert injector._load_secrets(tmp_path) == {
            "GITHUB_TOKEN": "ghp_abc123",
            "ANTHROPIC_API_KEY": "sk-ant-xyz",
        }

    def test_ignores_subdirectories(self, tmp_path):
        (tmp_path / "subdir").mkdir()
        (tmp_path / "TOKEN").write_text("value")
        assert injector._load_secrets(tmp_path) == {"TOKEN": "value"}


class TestLoadAllowedSecrets:
    def test_empty_input(self):
        assert injector._load_allowed_secrets("") == {}

    def test_parses_multiple_hosts(self):
        raw = (
            "api.github.com=GITHUB_TOKEN\n"
            "api.anthropic.com=ANTHROPIC_API_KEY,CLAUDE_CODE_OAUTH_TOKEN"
        )
        assert injector._load_allowed_secrets(raw) == {
            "api.github.com": {"GITHUB_TOKEN"},
            "api.anthropic.com": {"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"},
        }

    def test_strips_whitespace(self):
        raw = "  api.github.com = GITHUB_TOKEN , GITLAB_TOKEN \n\n"
        assert injector._load_allowed_secrets(raw) == {
            "api.github.com": {"GITHUB_TOKEN", "GITLAB_TOKEN"}
        }

    def test_skips_lines_without_a_host(self):
        assert injector._load_allowed_secrets("=SOME_SECRET") == {}


class TestRequest:
    """request() calls ctx.log.warn on the fail-closed path, so it needs an
    active addon context even though it isn't exercising `load`."""

    def test_host_not_in_allowed_secrets_is_untouched(self, monkeypatch):
        monkeypatch.setattr(injector, "ALLOWED_SECRETS", {"api.github.com": {"GITHUB_TOKEN"}})
        monkeypatch.setattr(injector, "SECRETS", {"GITHUB_TOKEN": "real-token"})
        flow = _flow("evil.example.com", {"Authorization": "Bearer INJECT=GITHUB_TOKEN"})

        with taddons.context(injector):
            injector.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer INJECT=GITHUB_TOKEN"

    def test_marker_substituted_preserving_surrounding_text(self, monkeypatch):
        monkeypatch.setattr(injector, "ALLOWED_SECRETS", {"api.github.com": {"GITHUB_TOKEN"}})
        monkeypatch.setattr(injector, "SECRETS", {"GITHUB_TOKEN": "real-token"})
        flow = _flow("api.github.com", {"Authorization": "Bearer INJECT=GITHUB_TOKEN"})

        with taddons.context(injector):
            injector.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer real-token"

    def test_header_stripped_when_secret_not_in_hosts_allowlist(self, monkeypatch):
        monkeypatch.setattr(injector, "ALLOWED_SECRETS", {"api.github.com": {"OTHER_SECRET"}})
        monkeypatch.setattr(injector, "SECRETS", {"GITHUB_TOKEN": "real-token"})
        flow = _flow("api.github.com", {"Authorization": "Bearer INJECT=GITHUB_TOKEN"})

        with taddons.context(injector):
            injector.request(flow)

        assert "Authorization" not in flow.request.headers

    def test_header_stripped_when_secret_allowed_but_not_mounted(self, monkeypatch):
        monkeypatch.setattr(injector, "ALLOWED_SECRETS", {"api.github.com": {"GITHUB_TOKEN"}})
        monkeypatch.setattr(injector, "SECRETS", {})
        flow = _flow("api.github.com", {"Authorization": "Bearer INJECT=GITHUB_TOKEN"})

        with taddons.context(injector):
            injector.request(flow)

        assert "Authorization" not in flow.request.headers

    def test_whole_header_dropped_if_any_marker_in_it_is_unauthorized(self, monkeypatch):
        monkeypatch.setattr(injector, "ALLOWED_SECRETS", {"api.github.com": {"GITHUB_TOKEN"}})
        monkeypatch.setattr(injector, "SECRETS", {"GITHUB_TOKEN": "real-token", "OTHER": "x"})
        flow = _flow("api.github.com", {"X-Two": "INJECT=GITHUB_TOKEN INJECT=OTHER"})

        with taddons.context(injector):
            injector.request(flow)

        assert "X-Two" not in flow.request.headers

    def test_only_headers_with_markers_are_touched(self, monkeypatch):
        monkeypatch.setattr(injector, "ALLOWED_SECRETS", {"api.github.com": {"GITHUB_TOKEN"}})
        monkeypatch.setattr(injector, "SECRETS", {"GITHUB_TOKEN": "real-token"})
        flow = _flow(
            "api.github.com",
            {
                "Authorization": "Bearer INJECT=GITHUB_TOKEN",
                "X-Plain": "no marker here",
            },
        )

        with taddons.context(injector):
            injector.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer real-token"
        assert flow.request.headers["X-Plain"] == "no marker here"


class TestLoad:
    def test_builds_anchored_escaped_host_regex(self, monkeypatch):
        monkeypatch.setattr(
            injector,
            "ALLOWED_SECRETS",
            {"api.github.com": {"GITHUB_TOKEN"}, "api.anthropic.com": {"ANTHROPIC_API_KEY"}},
        )

        with taddons.context(injector) as tctx:
            injector.load(None)
            (pattern,) = tctx.options.allow_hosts

        assert re.fullmatch(pattern, "api.github.com")
        assert re.fullmatch(pattern, "api.github.com:443")
        assert not re.fullmatch(pattern, "evil-api.github.com")
        assert not re.fullmatch(pattern, "api.github.com.evil.com")

    def test_allow_hosts_untouched_when_no_hosts_configured(self, monkeypatch):
        monkeypatch.setattr(injector, "ALLOWED_SECRETS", {})

        with taddons.context(injector) as tctx:
            default = list(tctx.options.allow_hosts)
            injector.load(None)
            assert list(tctx.options.allow_hosts) == default
