package sanitizer

import (
	"regexp"

	"github.com/microcosm-cc/bluemonday"
)

var (
	// Balanced policy: Allows basic formatting while being strict on dangerous content
	policy = func() *bluemonday.Policy {
		p := bluemonday.StrictPolicy()

		// Allow basic structural and formatting tags (important for readability)
		p.AllowElements("p", "br", "hr", "strong", "em", "b", "i", "u", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "blockquote")

		// Allow tables (as requested)
		p.AllowElements("table", "thead", "tbody", "tr", "th", "td")

		// Allow safe links (but strip dangerous attributes)
		p.AllowAttrs("href").OnElements("a")
		p.AllowAttrs("title").OnElements("a")

		// Allow basic alignment and styling where safe
		p.AllowAttrs("align").OnElements("p", "div", "table", "th", "td")

		return p
	}()

	// Regex for prompt-injection specific cleaning.
	// The sanitizer aggressively strips anything with no legitimate place in an API response.
	// Complex injection pattern detection is handled by Coraza SecLang rules.
	commentRe   = regexp.MustCompile(`<!--[\s\S]*?-->`)
	zeroWidthRe = regexp.MustCompile(`[\x{200b}\x{200c}\x{200d}\x{feff}\x{200e}\x{200f}]`)
)

func Sanitize(body []byte) []byte {
	if len(body) == 0 {
		return body
	}

	s := string(body)

	// 1. Remove HTML comments (common hiding spot)
	s = commentRe.ReplaceAllString(s, "")

	// 2. Apply bluemonday policy (strips dangerous tags/attributes, keeps tables + formatting)
	s = policy.Sanitize(s)

	// 3. Remove zero-width and invisible Unicode characters
	s = zeroWidthRe.ReplaceAllString(s, "")

	return []byte(s)
}
