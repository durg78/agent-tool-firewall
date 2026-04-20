# ATF Usage Guide

## Starting ATF

```bash
./atf-proxy
```

Default listen port is **3123**. Change it with:
```bash
./atf-proxy -port 8080
```

## Configuring Your Agent

Set the standard proxy environment variables before launching your tool:

```bash
export http_proxy=http://localhost:3123
export https_proxy=http://localhost:3123
export no_proxy=localhost,127.0.0.1,::1
```

### Tool-Specific Notes

- **OpenWebUI**: Set the env vars + enable "Trust Proxy Environment" in settings.
- **Hermes, Claude Code, OpenClaw, LangChain, etc.**: Usually respect the `http_proxy` / `https_proxy` variables automatically.

## Configuration (`config/config.yaml`)

```yaml
port: 3123
prompt_injection_threshold: 7
max_body_size_mb: 8

logging:
  enabled: true
  format: JSON
  destination: ./logs/atf-audit.log

coraza:
  rules_file: rules/custom.rules

# Request protection
request_protection:
  enabled: true
  # See config.yaml for full whitelist configuration
```

## Testing

```bash
# Start test server
cd test/malicious && python3 -m http.server 8000

# Run tests
./run_tests.sh
```

All malicious tests should return **403 Forbidden**.

## Logs

Written to `logs/atf-audit.log` (JSON format).

Request protection events are logged with:
- `REQUEST BLOCKED:` - Request blocked due to sensitive data
- `REQUEST WARNING:` - Sensitive data stripped from request

## Security Notes

- ATF inspects **responses** (prompt injection protection)
- ATF also inspects **outgoing requests** (sensitive data leakage protection)
- Sanitization happens before rules are applied
- Rules are fully customizable via `rules/custom.rules`
- No external runtime dependencies (pure Go)
- **Deny-by-default outbound protection**: Sensitive data patterns are blocked unless the destination is explicitly whitelisted

### Whitelist Configuration

The whitelist specifies which destinations are allowed to receive sensitive data. By default, only the following services are whitelisted:

- **OpenAI API** (`api.openai.com/*`) - Allows OpenAI keys (`sk-proj-`, `sk-svcacct-`)
- **Anthropic API** (`api.anthropic.com/*`) - Allows Anthropic keys (`sk-ant-`)
- **Stripe API** (`api.stripe.com/*`) - Allows Stripe keys (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`)
- **GitHub API** (`api.github.com/*`) - Allows GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- **Slack API** (`slack.com/*`) - Allows Slack tokens (`xoxb-`, `xoxp-`, etc.)

All other services (search engines, StackOverflow, debugging tools, etc.) are **denied** for all sensitive data patterns by default.

### Rule IDs

| Rule ID | Pattern | Action |
|---------|---------|--------|
| 900001 | AWS Access Key ID (AKIA) | Deny |
| 900002 | AWS Session Token (ASIA) | Deny |
| 900003 | GitHub Token | Deny |
| 900004 | GitLab Token | Deny |
| 900005 | Slack Token | Deny |
| 900006 | Stripe Key | Deny |
| 900007 | Stripe Restricted Key | Deny |
| 900008 | OpenAI Key | Deny |
| 900009 | Anthropic Key | Deny |
| 900010 | Google OAuth Refresh Token | Deny |
| 900011-900014 | Database Connection Strings | Deny |
| 900015 | Private Key Material | Deny |
| 900016-900018 | Cloud Metadata SSRF | Deny |
| 900019 | Internal/Private IP Access | Deny |
| 900020-900022 | Generic Code-Context Leakage | Deny |

---
