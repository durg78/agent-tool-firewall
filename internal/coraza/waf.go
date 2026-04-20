package coraza

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/durg78/agent-tool-firewall/internal/config"
)

// WAF handles both response and request protection using Coraza
type WAF struct {
	waf             coraza.WAF
	cfg             *config.Config
	outboundEnabled bool
}

// DetectionResult holds the result of sensitive data detection
type DetectionResult struct {
	Found    bool
	RuleID   int
	Location string // "header", "body", or "args"
}

// CheckResult holds the complete inspection result
type CheckResult struct {
	Allowed         bool
	Blocked         bool
	Message         string
	Detections      []DetectionResult
	WhitelistMatch  *config.RequestWhitelistEntry
}

// New creates a new WAF instance with both response and request protection
func New(cfg *config.Config) (*WAF, error) {
	w := &WAF{
		cfg:             cfg,
		outboundEnabled: cfg.RequestProtection.Enabled,
	}

	// Create Coraza WAF config
	wafConfig := coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecResponseBodyAccess On
			SecResponseBodyMimeType text/html text/plain application/json application/xml */*
			SecResponseBodyLimit 10485760
			SecResponseBodyLimitAction Reject
			SecAuditLogFormat ` + cfg.Logging.Format + `
			SecAuditLogParts "ABCFHZ"
			SecAuditLog ` + cfg.Logging.Destination + `
		`).
		WithDirectivesFromFile(cfg.Coraza.RulesFile)

	// Create the WAF
	corazaWAF, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Coraza WAF: %w", err)
	}
	w.waf = corazaWAF

	log.Printf("ATF: Coraza WAF initialized with response protection")
	if w.outboundEnabled {
		log.Printf("ATF: Request protection enabled with %d whitelist entries", len(cfg.RequestProtection.Whitelist))
	}
	return w, nil
}

// ProcessRequestHeaders inspects outgoing request headers for sensitive data
func (w *WAF) ProcessRequestHeaders(req *http.Request) *CheckResult {
	result := &CheckResult{
		Allowed:         false,
		Blocked:         false,
		Detections:      []DetectionResult{},
	}

	if !w.outboundEnabled {
		result.Allowed = true
		result.Message = "Request protection disabled"
		return result
	}

	// Create Coraza transaction for outgoing request inspection
	tx := w.waf.NewTransaction()
	defer tx.ProcessLogging()
	defer tx.Close()

	// Process request through Coraza - add headers manually
	tx.ProcessRequestHeaders()

	// Add request headers to transaction for inspection
	for key, values := range req.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}

	// Set the request method and URI
	tx.AddRequestHeader(":method", req.Method)
	tx.AddRequestHeader(":path", req.URL.Path)
	tx.AddRequestHeader(":scheme", req.URL.Scheme)
	tx.AddRequestHeader(":authority", req.Host)

	// Check for Coraza interruption (security blocks)
	interruption := tx.Interruption()
	if interruption != nil {
		result.Blocked = true
		result.Allowed = false
		result.Message = fmt.Sprintf("Request blocked by Coraza rule %d", interruption.RuleID)
		log.Printf("REQUEST BLOCKED (Coraza): %s", result.Message)
		return result
	}

	// Check for sensitive data detection rules (900000+ range)
	detectedRuleIDs := w.getDetectedRuleIDs(tx)
	for _, ruleID := range detectedRuleIDs {
		result.Detections = append(result.Detections, DetectionResult{
			Found:    true,
			RuleID:   ruleID,
			Location: "header",
		})
	}

	// Find matching whitelist entry
	matchingEntry, matched := w.findMatchingWhitelist(req.URL.String())
	result.WhitelistMatch = matchingEntry

	if !matched {
		// No whitelist match - check if sensitive data was detected
		if len(result.Detections) > 0 {
			result.Blocked = true
			result.Message = fmt.Sprintf(
				"Request blocked: sensitive data (rule %d) to non-whitelisted destination %s",
				result.Detections[0].RuleID,
				req.URL.Host,
			)
			log.Printf("REQUEST BLOCKED: %s", result.Message)
			return result
		}

		// No sensitive data, allow request
		result.Allowed = true
		result.Message = fmt.Sprintf("Request allowed (non-whitelisted destination %s, no sensitive data)", req.URL.Host)
		return result
	}

	// Whitelist matched - check if detected rule IDs are allowed
	allowedRuleIDs := make(map[int]bool)
	for _, ruleID := range matchingEntry.AllowedRuleIDs {
		allowedRuleIDs[ruleID] = true
	}

	// Check for unauthorized sensitive data
	var unauthorizedRules []int
	for _, detection := range result.Detections {
		if !allowedRuleIDs[detection.RuleID] {
			unauthorizedRules = append(unauthorizedRules, detection.RuleID)
		}
	}

	if len(unauthorizedRules) > 0 {
		// Block request with unauthorized sensitive data
		result.Blocked = true
		result.Message = fmt.Sprintf(
			"Request blocked: unauthorized sensitive data (rules %v) to %s",
			unauthorizedRules,
			req.URL.Host,
		)
		log.Printf("REQUEST BLOCKED: %s", result.Message)
		return result
	}

	// All good - request is whitelisted and data types are allowed
	result.Allowed = true
	result.Message = fmt.Sprintf("Request allowed (whitelisted: %s)", matchingEntry.Description)
	return result
}

// ProcessRequestBody inspects outgoing request body for sensitive data
func (w *WAF) ProcessRequestBody(req *http.Request, body []byte) *CheckResult {
	result := &CheckResult{
		Allowed:         false,
		Blocked:         false,
		Detections:      []DetectionResult{},
	}

	if !w.outboundEnabled {
		result.Allowed = true
		result.Message = "Outbound protection disabled"
		return result
	}

	// Create Coraza transaction for outgoing request inspection
	tx := w.waf.NewTransaction()
	defer tx.ProcessLogging()
	defer tx.Close()

	// Set request metadata
	tx.AddRequestHeader(":method", req.Method)
	tx.AddRequestHeader(":path", req.URL.Path)
	tx.AddRequestHeader(":scheme", req.URL.Scheme)
	tx.AddRequestHeader(":authority", req.Host)

	// Add request headers
	for key, values := range req.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}

	// Add query parameters to ARGS_GET
	if req.URL.RawQuery != "" {
		parsed, err := url.ParseQuery(req.URL.RawQuery)
		if err == nil {
			for key, values := range parsed {
				for _, value := range values {
					tx.AddGetRequestArgument(key, value)
				}
			}
		}
	}

	// Add request body
	if len(body) > 0 {
		_, _, err := tx.WriteRequestBody(body)
		if err != nil {
			log.Printf("Failed to write request body to Coraza: %v", err)
		}
	}

	// Process request body through Coraza
	interruption, err := tx.ProcessRequestBody()
	if err != nil {
		result.Blocked = true
		result.Message = fmt.Sprintf("Request blocked by Coraza error: %v", err)
		log.Printf("REQUEST BLOCKED: %s", result.Message)
		return result
	}

	if interruption != nil {
		result.Blocked = true
		result.Allowed = false
		result.Message = fmt.Sprintf("Request blocked by Coraza rule %d", interruption.RuleID)
		log.Printf("REQUEST BLOCKED (Coraza): %s", result.Message)
		return result
	}

	// Check for sensitive data detection rules (900000+ range)
	detectedRuleIDs := w.getDetectedRuleIDs(tx)
	for _, ruleID := range detectedRuleIDs {
		result.Detections = append(result.Detections, DetectionResult{
			Found:    true,
			RuleID:   ruleID,
			Location: "body",
		})
	}

	// Find matching whitelist entry
	matchingEntry, matched := w.findMatchingWhitelist(req.URL.String())
	result.WhitelistMatch = matchingEntry

	if !matched {
		// No whitelist match - check if sensitive data was detected
		if len(result.Detections) > 0 {
			result.Blocked = true
			result.Message = fmt.Sprintf(
				"Request blocked: sensitive data (rule %d) in body to non-whitelisted destination %s",
				result.Detections[0].RuleID,
				req.URL.Host,
			)
			log.Printf("REQUEST BLOCKED: %s", result.Message)
			return result
		}

		// No sensitive data, allow request
		result.Allowed = true
		result.Message = fmt.Sprintf("Request allowed (non-whitelisted destination %s, no sensitive data in body)", req.URL.Host)
		return result
	}

	// Whitelist matched - check if detected rule IDs are allowed
	allowedRuleIDs := make(map[int]bool)
	for _, ruleID := range matchingEntry.AllowedRuleIDs {
		allowedRuleIDs[ruleID] = true
	}

	// Check for unauthorized sensitive data
	var unauthorizedRules []int
	for _, detection := range result.Detections {
		if !allowedRuleIDs[detection.RuleID] {
			unauthorizedRules = append(unauthorizedRules, detection.RuleID)
		}
	}

	if len(unauthorizedRules) > 0 {
		// Block request with unauthorized sensitive data
		result.Blocked = true
		result.Message = fmt.Sprintf(
			"Request blocked: unauthorized sensitive data (rules %v) in body to %s",
			unauthorizedRules,
			req.URL.Host,
		)
		log.Printf("REQUEST BLOCKED: %s", result.Message)
		return result
	}

	// All good - request is whitelisted and data types are allowed
	result.Allowed = true
	result.Message = fmt.Sprintf("Request allowed (whitelisted: %s)", matchingEntry.Description)
	return result
}

// getDetectedRuleIDs extracts rule IDs from matched rules in the transaction.
// Filters for rules in the 900000+ range (sensitive data detection).
func (w *WAF) getDetectedRuleIDs(tx types.Transaction) []int {
	var detectedRules []int
	seen := make(map[int]bool)

	for _, mr := range tx.MatchedRules() {
		ruleID := mr.Rule().ID()
		if ruleID >= 900000 && !seen[ruleID] {
			detectedRules = append(detectedRules, ruleID)
			seen[ruleID] = true
		}
	}
	return detectedRules
}

// findMatchingWhitelist finds a matching whitelist entry for the given URL.
// Supports three pattern types:
//   - regex: if the pattern starts with "re:", it's compiled as a regex
//   - wildcard: "*.example.com" or "example.com/*"
//   - exact: literal substring match
func (w *WAF) findMatchingWhitelist(urlStr string) (*config.RequestWhitelistEntry, bool) {
	for i := range w.cfg.RequestProtection.Whitelist {
		entry := &w.cfg.RequestProtection.Whitelist[i]
		pattern := entry.URLPattern

		// Regex pattern (prefixed with "re:")
		if strings.HasPrefix(pattern, "re:") {
			regexPattern := strings.TrimPrefix(pattern, "re:")
			matched, _ := regexp.MatchString(regexPattern, urlStr)
			if matched {
				return entry, true
			}
			continue
		}

		// Wildcard domain (*.example.com)
		if strings.HasPrefix(pattern, "*.") {
			domain := strings.TrimPrefix(pattern, "*.")
			if strings.HasSuffix(urlStr, "."+domain) || strings.Contains(urlStr, domain) {
				return entry, true
			}
			continue
		}

		// Wildcard path (example.com/*)
		if strings.Contains(pattern, "/*") {
			baseDomain := strings.Split(pattern, "/*")[0]
			if strings.Contains(urlStr, baseDomain) {
				return entry, true
			}
			continue
		}

		// Exact/substring match
		if strings.Contains(urlStr, pattern) {
			return entry, true
		}
	}
	return nil, false
}

// ProcessResponseBody handles response body inspection (existing functionality)
func (w *WAF) ProcessResponseBody(body []byte, statusCode int) (bool, string, error) {
	tx := w.waf.NewTransaction()
	defer tx.ProcessLogging()
	defer tx.Close()

	statusText := http.StatusText(statusCode)
	tx.ProcessResponseHeaders(statusCode, statusText)
	tx.AddResponseHeader("Content-Type", "text/html")

	if len(body) > 0 {
		_, _, err := tx.WriteResponseBody(body)
		if err != nil {
			return false, "", err
		}
	}

	interruption, err := tx.ProcessResponseBody()
	if err != nil {
		return false, "", err
	}

	if interruption != nil {
		msg := "Prompt injection blocked by ATF"
		if interruption.RuleID != 0 {
			msg = fmt.Sprintf("Blocked by rule %d", interruption.RuleID)
		}
		return true, msg, nil
	}

	return false, "", nil
}

// IsRequestEnabled returns whether request protection is enabled
func (w *WAF) IsRequestEnabled() bool {
	return w.outboundEnabled
}

// CheckInterruption checks if a Coraza transaction was interrupted
func (w *WAF) CheckInterruption(interruption *types.Interruption) (bool, string) {
	if interruption == nil {
		return false, ""
	}

	msg := "Request blocked by security policy"
	if interruption.RuleID != 0 {
		msg = fmt.Sprintf("Blocked by rule %d", interruption.RuleID)
	}

	return true, msg
}
