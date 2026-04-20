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

---
