# Response Protection - SecLang Rule-Based Detection

## Summary

Request protection uses Coraza WAF SecLang rules (IDs 900001-900008) to detect sensitive data in outgoing requests. Destinations are whitelisted with explicit permission for specific rule IDs.

## Architecture

### SecLang Rules (`rules/custom.rules`)

Sensitive data detection rules (phase 1, pass):

| Rule ID | Detection | Header |
|---------|-----------|--------|
| 900001 | JWT token (Bearer eyJ) | Authorization |
| 900002 | JWT token (eyJ pattern) | Authorization |
| 900003 | API key (sk- prefix) | X-API-Key |
| 900004 | API key (api_ prefix) | X-API-Key |
| 900005 | API key (sk_live_/sk_test_) | X-API-Key |
| 900006 | Basic auth credentials | Authorization |
| 900007 | Bearer token (non-JWT) | Authorization |
| 900008 | Potential token in cookie | Cookie |

### Core Implementation (`internal/coraza/waf.go`)

**Methods:**
- `ProcessRequestHeaders(req *http.Request) *CheckResult` - Inspects outgoing request headers via Coraza transaction
- `ProcessRequestBody(req *http.Request, body []byte) *CheckResult` - Inspects outgoing request body via Coraza transaction
- `ProcessResponseBody(body []byte) (bool, string, error)` - Inspects response body via Coraza transaction
- `IsRequestEnabled() bool` - Returns whether request protection is enabled

**Key Design Decisions:**
1. **Coraza Transactions**: Both request and response inspection use Coraza transactions for consistent rule evaluation
2. **Header Processing**: Request headers are added to the transaction via `AddRequestHeader()` for rule matching
3. **Body Processing**: Request/response bodies are processed via `WriteRequestBody()` / `WriteResponseBody()`
4. **Whitelist Matching**: URL patterns matched against destination, allowed rule IDs verified against detected sensitive data

### Request Flow (`internal/proxy/handler.go`)

1. Read request body (if present) for inspection
2. Call `waf.ProcessRequestHeaders()` - creates Coraza transaction, adds headers, checks for sensitive data
3. Whitelist matching:
   - If destination not whitelisted AND sensitive data detected → BLOCK
   - If destination whitelisted BUT unauthorized rule IDs detected → BLOCK
   - Otherwise → ALLOW
4. Forward request to destination
5. Process response body through `waf.ProcessResponseBody()` for prompt injection detection

## Configuration

Request protection is configured via `config/config.yaml`:

```yaml
request_protection:
  enabled: true

  whitelist:
    - url_pattern: "api.openai.com/*"
      allowed_rule_ids: [900001, 900002, 900007]
      description: "OpenAI API service"

    - url_pattern: "api.anthropic.com/*"
      allowed_rule_ids: [900003, 900004, 900005]
      description: "Anthropic Claude API"
```

### Pattern Matching Types

The whitelist supports four pattern matching strategies:

1. **Wildcard Domain** (`*.example.com`) — Matches any subdomain
   - `*.auth0.com` matches `login.auth0.com`, `oauth.auth0.com`

2. **Wildcard Path** (`example.com/*`) — Matches any path on a domain
   - `api.openai.com/*` matches `api.openai.com/v1/chat`, `api.openai.com/v1/models`

3. **Regex** (`re:^https://...`) — Full regex pattern for complex matching
   - `re:^https://[a-z0-9-]+\\.mycompany\\.com/.*` matches all subdomains
   - `re:^https://oauth2\\.google\\.com/.*` matches Google OAuth endpoints

4. **Exact/Substring** (`api.example.com`) — Literal substring match
   - `slack.com/*` matches any URL containing `slack.com`

### Whitelist Behavior

- **Matched destinations**: Requests allowed if detected rule IDs are in allowed list
- **Non-whitelisted destinations**: Requests blocked if any sensitive data (rules 900001-900008) detected
- **Coraza security blocks**: Separate from sensitive data - blocks via interruption
- **Service presets**: Default config includes presets for OpenAI, Anthropic, GitHub, Slack, Notion, Discord, AWS, and Stripe

## Testing

All tests pass:
```bash
go test ./... -v
```

Coraza-specific tests:
- `TestProcessRequestHeaders_OutboundBlocked` - Tests Coraza blocking
- `TestProcessRequestHeaders_OutboundAllowed` - Tests allowed requests
- `TestProcessRequestBody_SensitiveData` - Tests body inspection
- `TestProcessResponseBody_SafeContent` - Tests response inspection

## Migration from Legacy Implementation

### Before (Go Pattern Matching - Deprecated)
```go
// Manual regex pattern matching in Go
detections := w.detectSensitiveDataInHeaders(req)
detections := w.detectSensitiveDataInBody(body)
```

### After (SecLang Rule-Based)
```go
// Coraza transaction-based inspection with rule ID matching
tx := w.waf.NewTransaction()
tx.ProcessRequestHeaders()
for key, values := range req.Header {
    for _, value := range values {
        tx.AddRequestHeader(key, value)
    }
}
// Check detected rule IDs against whitelist allowed_rule_ids
```

## Benefits

1. **Single Source of Truth**: Rules defined once in SecLang, not duplicated in config and code
2. **Direct Mapping**: Whitelist references rule IDs directly (900001, 900002, etc.)
3. **Maintainability**: Add new detection rules in SecLang file only
4. **Audit Logging**: Unified audit logging via Coraza's audit system
5. **Extensibility**: New detection rules added via SecLang, not code changes

## Adding New Request Detection Rules

1. Add new SecLang rule to `rules/custom.rules` with unique ID in 900000+ range
2. Update config documentation with new rule ID
3. Whitelist destinations that should be allowed to send this data type

Example:
```sec
SecRule REQUEST_HEADERS:X-Custom-Auth "@rx ^secret_" \
"id:900009,phase:1,pass,log,tag:'sensitive-data',tag:'custom_auth',msg:'Custom auth token detected'"
```

Then update whitelist:
```yaml
- url_pattern: "api.example.com/*"
  allowed_rule_ids: [900009]
  description: "Example API"
```
