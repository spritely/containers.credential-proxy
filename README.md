# containers.credential-proxy

A mitmproxy-based egress proxy that injects real credentials into outbound requests so a calling devcontainer never has to hold its own secrets.

A client requests a secret by embedding an `INJECT=<NAME>` marker in a header value; the proxy substitutes the real secret in place. This works both for markers written directly into a header value (e.g. `Authorization: Bearer INJECT=GITHUB_TOKEN`) and for markers carried inside `Authorization: Basic` credentials, which the proxy base64-decodes, substitutes, and re-encodes (e.g. NuGet or git restoring from GitHub Packages). `ALLOWED_SECRETS` pins which secret names each host may request; a marker for a secret that is not allowed for the host, or not mounted, causes the whole header to be dropped rather than forwarded.
