// Package safeoutput removes terminal controls and common credential forms
// from text before it reaches human-readable logs or reports.
package safeoutput

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
)

// Redaction is best-effort: it covers the credential forms below, and new
// vendor syntaxes keep appearing. Raw artifacts are protected by file
// permissions, not by this package.
//
// Shared fragments. Between a keyword and its secret there can be a run of
// type numbers ("7", "10") and encoding or algorithm qualifiers
// ("encrypted", Junos "ascii-text", IS-IS "hmac-md5 encrypted"). The whole
// run must be consumed so the secret itself is what gets redacted. Runs stay
// on one line so a keyword at the end of a line never redacts the next one.
const (
	secretValue     = `("(?:\\.|[^"\\])*"|'[^']*'|[^\s,;]+)`
	secretQualifier = `(?:(?:\d{1,2}|encrypted|unencrypted|ascii-text|ascii|hexadecimal|hex|cipher|hidden|clear|text|md5|sha256|sha512|hmac-md5|hmac-sha1|hmac-sha-1|hmac-sha-256)[ \t]+){0,3}`

	sensitiveKeywords = `password-encrypt|password|passwd|encrypted-password|secret|community|token|authentication-key|authentication-password|auth-key|md5-key|key-string|key-octet-string|privacy-key|privacy-password|wpa-psk|wpa-passphrase|cak`
	xmlSecretElements = `password|secret|community|token|pre-shared-key|encrypted-password|authentication-key|authentication-password|privacy-key|privacy-password|key-string|md5-key|auth-key|cak|wpa-psk`
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?im)\b((?:tacacs-server|radius-server)\s+key)\b([ \t]+(?:\d{1,2}[ \t]+)?)` + secretValue),
	// Junos MACsec puts "cak" (secret) or "ckn" (a name) after
	// pre-shared-key; IOS "mka pre-shared-key key-chain NAME" names a chain.
	regexp.MustCompile(`(?im)\b(pre-shared-key)\b([ \t]+(?:(?:local|remote|cak)[ \t]+)?` + secretQualifier + `)` + secretValue),
	regexp.MustCompile(`(?im)\b(authentication-key)\b([ \t]+\d+[ \t]+(?:md5|sha1|sha256|sha512)[ \t]+(?:\d{1,2}[ \t]+)?)` + secretValue),
	regexp.MustCompile(`(?im)\b(message-digest-key)\b([ \t]+\d+[ \t]+md5[ \t]+(?:\d{1,2}[ \t]+)?)` + secretValue),
	regexp.MustCompile(`(?im)\b(auth)\b([ \t]+(?:md5|sha|sha-\d+|sha\d+)[ \t]+)` + secretValue),
	regexp.MustCompile(`(?im)\b(priv)\b([ \t]+(?:des|3des|aes(?:[ \t]+(?:128|192|256))?)[ \t]+)` + secretValue),
	// snmp-server host ADDR [vrf V] [informs|traps] [version 1|2c|3 [auth|noauth|priv]] COMMUNITY
	regexp.MustCompile(`(?im)\b(snmp-server[ \t]+host[ \t]+\S+(?:[ \t]+vrf[ \t]+\S+)?(?:[ \t]+(?:informs|traps))?(?:[ \t]+version[ \t]+(?:1|2c|3(?:[ \t]+(?:auth|noauth|priv))?))?)([ \t]+)` + secretValue),
	regexp.MustCompile(`(?i)\b(` + sensitiveKeywords + `)\b([ \t]+` + secretQualifier + `|\s*[:=]\s*)` + secretValue),
	regexp.MustCompile(`(?i)\b(authorization|proxy-authorization)\b(\s*:\s*)(?:basic|bearer)\s+([^\s,;]+)`),
	regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?is)<(?:` + xmlSecretElements + `)(?:\s[^>]*)?>.*?</(?:` + xmlSecretElements + `)>`),
}

// A captured "value" that is itself syntax, not a secret, is left alone: a
// following keyword (whose own rule redacts its value), a key-chain
// reference, or a MACsec connectivity-key name.
var nonSecretValues = func() map[string]bool {
	words := map[string]bool{"key-chain": true, "keychain": true, "ckn": true, "[redacted]": true}
	for _, word := range strings.Split(sensitiveKeywords, "|") {
		words[word] = true
	}
	return words
}()

func redactMatches(pattern *regexp.Regexp, value string, keep map[string]bool) string {
	return pattern.ReplaceAllStringFunc(value, func(match string) string {
		parts := pattern.FindStringSubmatch(match)
		if len(parts) < 4 {
			return "[REDACTED]"
		}
		if word := strings.ToLower(parts[3]); nonSecretValues[word] || keep[word] {
			return match
		}
		return parts[1] + parts[2] + "[REDACTED]"
	})
}

// A bare "key <value>" is a secret in tacacs/radius blocks and
// "crypto isakmp key", but the same word also introduces harmless commands
// ("key chain NAME", "crypto key generate rsa") and key-chain entries
// ("key 0 secret ..."). It runs after the keyword rules so the entry's own
// keyword redacts its value. A lone "key 1" (a key-chain ID) is still
// redacted: it cannot be told apart from a numeric TACACS/RADIUS key.
var bareKey = regexp.MustCompile(`(?im)((?:^|[ \t])key)\b([ \t]+(?:\d{1,2}[ \t]+)?)` + secretValue)

var bareKeySubcommands = map[string]bool{
	"chain": true, "generate": true, "zeroize": true, "import": true, "export": true, "pubkey-chain": true,
	"storage": true, "encrypt": true, "decrypt": true, "move": true, "lock": true, "unlock": true,
}

// Quoted fields also occur inside diagnostic prose, outside a JSON document.
var quotedSecret = regexp.MustCompile(`(?i)("(?:password|passwd|secret|community|token|access[_-]token|refresh[_-]token|api[_-]key|client[_-]secret|private[_-]key)"\s*:\s*)("(?:\\.|[^"\\])*"|[^\s,}]+)`)

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	switch key {
	case "password", "passwd", "encryptedpassword", "secret", "community", "token", "accesstoken", "refreshtoken", "apikey", "clientsecret", "privatekey", "authorization", "proxyauthorization", "authenticationkey", "authenticationpassword", "authkey", "md5key", "keystring", "presharedkey", "privacykey", "privacypassword", "cak", "wpapsk", "keyoctetstring":
		return true
	}
	return false
}

func redactDocument(value interface{}) interface{} {
	switch node := value.(type) {
	case map[string]interface{}:
		for key, child := range node {
			if sensitiveKey(key) {
				node[key] = "[REDACTED]"
			} else {
				node[key] = redactDocument(child)
			}
		}
	case []interface{}:
		for i, child := range node {
			node[i] = redactDocument(child)
		}
	case string:
		return redactText(node)
	}
	return value
}

func redactText(value string) string {
	value = quotedSecret.ReplaceAllString(value, `${1}"[REDACTED]"`)
	for _, pattern := range sensitivePatterns {
		value = redactMatches(pattern, value, nil)
	}
	return redactMatches(bareKey, value, bareKeySubcommands)
}

// Sanitize neutralises terminal escape/control sequences and redacts common
// credential representations while retaining enough surrounding text for
// diagnosis.
func Sanitize(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 && (r < 0x7f || r > 0x9f) {
			return r
		}
		return -1
	}, value)
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		var document interface{}
		if decoder.Decode(&document) == nil {
			var extra interface{}
			if decoder.Decode(&extra) == io.EOF {
				if encoded, err := json.Marshal(redactDocument(document)); err == nil {
					return string(encoded)
				}
			}
		}
	}
	return redactText(value)
}

type sanitizingWriter struct {
	destination io.Writer
}

// NewWriter returns a writer that applies Sanitize to each complete write
// before forwarding it. It is intended for line-oriented human output, where
// fmt, slog, and similar callers emit one complete record per write.
func NewWriter(destination io.Writer) io.Writer {
	return &sanitizingWriter{destination: destination}
}

func (writer *sanitizingWriter) Write(content []byte) (int, error) {
	sanitized := []byte(Sanitize(string(content)))
	written, err := writer.destination.Write(sanitized)
	if err != nil {
		return 0, err
	}
	if written != len(sanitized) {
		return 0, io.ErrShortWrite
	}
	return len(content), nil
}

// Transcript data is an arbitrary byte stream, including echoed credentials.
// Only byte counts are retained; command outputs use the normal protected path.
type transcriptWriter struct {
	mu          sync.Mutex
	destination io.Writer
}

func NewTranscriptWriter(destination io.Writer) io.Writer {
	return &transcriptWriter{destination: destination}
}
func (w *transcriptWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(w.destination, "[channel data omitted; bytes=%d]\n", len(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}
