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
  response_only: true
  rules_file: rules/custom.rules
```

## Testing

```bash
# Start test server
cd test/malicious && python3 -m http.server 8000

# Run tests
./test.sh
```

All malicious tests should return **403 Forbidden**.

## Logs

Written to `logs/atf-audit.log` (JSON format).

## Security Notes

- ATF inspects **responses only**
- Sanitization happens before rules are applied
- Rules are fully customizable via `rules/custom.rules`
- No external runtime dependencies (pure Go)

---
