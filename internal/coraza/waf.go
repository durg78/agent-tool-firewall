package coraza

import (
	"fmt"
	"log"

	"github.com/corazawaf/coraza/v3"
	"github.com/durg78/agent-tool-firewall/internal/config"
)

type WAF struct {
	waf coraza.WAF
}

func New(cfg *config.Config) (*WAF, error) {
	config := coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess Off
			SecResponseBodyAccess On
			SecResponseBodyMimeType text/html text/plain application/json application/xml */*
			SecResponseBodyLimit 10485760
			SecResponseBodyLimitAction Reject
			SecAuditLogFormat ` + cfg.Logging.Format + `
			SecAuditLogParts "ABCFHZ"
			SecAuditLog ` + cfg.Logging.Destination + `
		`).
		WithDirectivesFromFile(cfg.Coraza.RulesFile)

	log.Printf("ATF: Loaded external rules from %s", cfg.Coraza.RulesFile)

	w, err := coraza.NewWAF(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF: %w", err)
	}

	return &WAF{waf: w}, nil
}

func (w *WAF) ProcessResponseBody(body []byte) (bool, string, error) {
	tx := w.waf.NewTransaction()
	defer tx.ProcessLogging()
	defer tx.Close()

	tx.ProcessResponseHeaders(200, "HTTP/1.1")
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
