# ATF (Agent-Tool-Firewall)

A minimal, standalone, high-performance outbound security proxy designed to protect local LLM agents from **indirect prompt injection attacks**.

### The Problem
Local LLM agents (OpenWebUI, Hermes, Claude Code, OpenClaw, etc.) make outbound web requests. Malicious websites can return hidden instructions (comments, `display:none` text, hidden DOM elements, etc.) that the LLM will follow. Most setups have no protection at this boundary.

### ATF's Approach
ATF is a transparent HTTP/HTTPS proxy that sits between your agent and the internet:

1. **Full standards-compliant proxy** — Works with standard `http_proxy` / `https_proxy` environment variables.
2. **Pure-Go HTML Sanitizer** — Uses `bluemonday` + targeted regex to strip dangerous/hidden content while preserving readability (tables, basic formatting, etc.).
3. **Embedded Coraza WAF** — Response-body-only inspection with powerful custom SecLang rules.
4. **Anomaly Scoring** — Sophisticated scoring system instead of brittle pattern matching.
5. **Configurable Threshold** — Blocking decision based on score (default ≥ 7).
6. **Safe Forwarding** — Only clean content is returned, prefixed with `[UNTRUSTED EXTERNAL DATA …]`.

### Key Features
- Single static Go binary (zero external dependencies)
- Full HTTP/HTTPS proxy support (`CONNECT` method included)
- Pure-Go implementation — no Python or external tools required
- External, human-maintainable SecLang rules with anomaly scoring
- Clean, readable output on safe pages (preserves tables and basic formatting)
- JSON/OCSF-compatible audit logging
- Designed for local LLM ecosystems

### Quick Start

```bash
# Build
go build -trimpath -ldflags="-s -w" -o atf-proxy ./cmd/atf-proxy

# Run
./atf-proxy
```

Then configure your agent:

```bash
export http_proxy=http://localhost:3123
export https_proxy=http://localhost:3123
export no_proxy=localhost,127.0.0.1,::1
```

See [USAGE.md](USAGE.md) for detailed per-tool instructions.

### Effectiveness
ATF provides strong protection against known indirect prompt injection vectors while maintaining low false-positive rates. The combination of aggressive sanitization and anomaly scoring makes it one of the more robust solutions available for local agentic systems.

---
