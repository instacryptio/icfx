package validate

import (
	"fmt"
	"regexp"
	"strings"
)

// maxAliasLen bounds the identity alias (a short, username-like public handle).
const maxAliasLen = 32

// aliasPattern is the allowed alias charset: lowercase ASCII letters, digits,
// hyphen, and underscore — a single word with no spaces. Kept deliberately
// narrow so an alias is safe as a filename component, a URL/CLI token, and a
// future directory-search key.
var aliasPattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// Alias validates an identity alias. The alias is optional (empty is allowed);
// when set it must be a single lowercase word of ASCII letters/digits plus '-'
// and '_', at most maxAliasLen characters, with no spaces or other
// punctuation. Callers should have already lowercased/trimmed user input.
func Alias(alias string) error {
	if alias == "" {
		return nil
	}
	if len(alias) > maxAliasLen {
		return fmt.Errorf("alias is too long (max %d characters)", maxAliasLen)
	}
	if !aliasPattern.MatchString(alias) {
		return fmt.Errorf("alias must be a single lowercase word using only letters, digits, '-' and '_' (no spaces)")
	}
	return nil
}

// NormalizeAlias lowercases and trims an inbound alias and returns it only when
// it satisfies Alias; otherwise it returns "". Use it at ingest points that take
// an alias from an untrusted or unnormalized source (a received lock, an
// imported bundle) so a non-conforming value is dropped rather than stored.
func NormalizeAlias(raw string) string {
	a := strings.ToLower(strings.TrimSpace(raw))
	if Alias(a) != nil {
		return ""
	}
	return a
}
