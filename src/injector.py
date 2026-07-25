"""Inject real credentials into outbound requests.

A client requests a secret by embedding INJECT=<NAME> in a header value; we
substitute the real value in place, keeping whatever the client wrote around
it (e.g. "Bearer ..." or "token ..."). ALLOWED_SECRETS is the actual security
boundary: it pins which secret names each host may request, so a compromised
container can't ask for GITHUB_TOKEN on an api.anthropic.com request.

ALLOWED_SECRETS is configured entirely through the ALLOWED_SECRETS
environment variable, one "host=SECRET1,SECRET2" mapping per line, so this
script never needs to change to support a new host or secret.
"""
import base64
import logging
import os
import re
from pathlib import Path

from mitmproxy import addonmanager, ctx, http

SECRETS_DIR = Path("/run/secrets")


def _load_secrets(secrets_dir: Path) -> dict[str, str]:
    if not secrets_dir.is_dir():
        return {}
    return {p.name: p.read_text().strip() for p in secrets_dir.iterdir() if p.is_file()}


def _load_allowed_secrets(raw: str) -> dict[str, set[str]]:
    allowed = {}
    for line in raw.splitlines():
        host, _, names = line.partition("=")
        host = host.strip()
        if not host:
            continue
        allowed[host] = {name.strip() for name in names.split(",") if name.strip()}
    return allowed


SECRETS = _load_secrets(SECRETS_DIR)
ALLOWED_SECRETS = _load_allowed_secrets(os.environ.get("ALLOWED_SECRETS", ""))

# A header value embeds this marker to request substitution, e.g. a client
# sends "token INJECT=GITHUB_TOKEN" and we replace just the marker text.
MARKER = re.compile(r"INJECT=([A-Z][A-Z0-9_]*)")


def load(_loader: addonmanager.Loader) -> None:
    # Intercept (MITM) only the hosts ALLOWED_SECRETS configures; every other
    # host is transparently tunnelled, so nothing else needs to trust our CA.
    hosts = "|".join(re.escape(host) for host in ALLOWED_SECRETS)
    if hosts:
        ctx.options.update(allow_hosts=[rf"^({hosts})(:\d+)?$"])


def _substitute(value: str, allowed: set[str], host: str, header: str) -> str | None:
    """Return `value` with its markers replaced, or None to drop the header.

    A value with no markers comes back unchanged, so callers can compare against
    the input to decide whether the header is worth rewriting at all.
    """
    markers = MARKER.findall(value)
    if not markers:
        return value
    unauthorized = [m for m in markers if m not in allowed or m not in SECRETS]
    if unauthorized:
        # Fail closed rather than forward the marker text upstream.
        logging.warning(
            f"Dropping header {header!r}: unauthorized or missing secret(s) "
            f"{', '.join(unauthorized)} for host {host}"
        )
        return None
    return MARKER.sub(lambda m: SECRETS[m.group(1)], value)


def _decode_basic(value: str) -> tuple[str, str] | None:
    """Split "Basic <base64>" into its scheme and the decoded "user:password".

    Basic clients (NuGet, pip, git over HTTPS) base64 their credentials, which
    hides the marker from a plain text substitution. None means this header is
    not a decodable Basic credential and should take the plain text path.
    """
    scheme, _, encoded = value.partition(" ")
    encoded = encoded.strip()
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        return scheme, base64.b64decode(encoded, validate=True).decode()
    except ValueError:
        # binascii.Error (bad base64) and UnicodeDecodeError are both ValueError.
        return None


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    allowed = ALLOWED_SECRETS.get(host)
    if not allowed:
        return
    for name, value in list(flow.request.headers.items()):
        basic = _decode_basic(value)
        original = basic[1] if basic else value
        injected = _substitute(original, allowed, host, name)
        if injected is None:
            del flow.request.headers[name]
        elif injected != original:
            flow.request.headers[name] = (
                f"{basic[0]} {base64.b64encode(injected.encode()).decode()}"
                if basic
                else injected
            )
