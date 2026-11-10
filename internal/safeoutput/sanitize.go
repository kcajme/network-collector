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

// Shared fragments. A type number ("7", "10") and/or an encoding qualifier
// ("encrypted", Junos "ascii-text") can sit between a keyword and the
// secret; both must be consumed so the secret itself is what gets redacted.
const (
	secretValue     = `("(?:\\.|[^"\\])*"|'[^']*'|[^\s,;]+)`
	secretQualifier = `(?:(?:encrypted|ascii-text|hexadecimal|cipher|hidden|clear|unencrypted|sha512|sha256)\s+)?`
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?im)\b((?:tacacs-server|radius-server)\s+key)\b(\s+(?:\d{1,2}\s+)?)` + secretValue),
	regexp.MustCompile(`(?im)\b(pre-shared-key)\b(\s+(?:local\s+|remote\s+)?(?:\d{1,2}\s+)?` + secretQualifier + `)` + secretValue),
	regexp.MustCompile(`(?im)\b(authentication-key)\b(\s+\d+\s+(?:md5|sha1|sha256|sha512)\s+(?:\d{1,2}\s+)?)` + secretValue),
	regexp.MustCompile(`(?im)\b(message-digest-key)\b(\s+\d+\s+md5\s+(?:\d{1,2}\s+)?)` + secretValue),
	regexp.MustCompile(`(?im)\b(auth)\b(\s+(?:md5|sha|sha-\d+|sha\d+)\s+)` + secretValue),
	regexp.MustCompile(`(?im)\b(priv)\b(\s+(?:des|3des|aes(?:\s+(?:128|192|256))?)\s+)` + secretValue),
	regexp.MustCompile(`(?i)\b(password-encrypt|password|passwd|encrypted-password|secret|community|token|authentication-key|authentication-password|auth-key|md5-key|key-string|privacy-key|privacy-password)\b(\s+(?:\d{1,2}\s+)?` + secretQualifier + `|\s*[:=]\s*)` + secretValue),
	regexp.MustCompile(`(?i)\b(authorization|proxy-authorization)\b(\s*:\s*)(?:basic|bearer)\s+([^\s,;]+)`),
	regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?is)<(?:password|secret|community|token|pre-shared-key|encrypted-password|authentication-key|authentication-password|privacy-key|privacy-password|key-string|md5-key|auth-key)(?:\s[^>]*)?>.*?</(?:password|secret|community|token|pre-shared-key|encrypted-password|authentication-key|authentication-password|privacy-key|privacy-password|key-string|md5-key|auth-key)>`),
}

// A bare "key <value>" is a secret in tacacs/radius blocks and
// "crypto isakmp key", but the same word also introduces harmless commands
// ("key chain NAME", "crypto key generate rsa"). Those words are left
// visible; anything else after "key" is treated as a secret. Matching stays
// on one line so a key-chain ID cannot swallow the next line.
var bareKey = regexp.MustCompile(`(?im)((?:^|[ \t])key)\b([ \t]+(?:\d{1,2}[ \t]+)?)` + secretValue)

var bareKeySubcommands = map[string]bool{
	"chain": true, "generate": true, "zeroize": true, "import": true, "export": true, "pubkey-chain": true,
	"storage": true, "encrypt": true, "decrypt": true, "move": true, "lock": true, "unlock": true,
}

func redactBareKey(value string) string {
	return bareKey.ReplaceAllStringFunc(value, func(match string) string {
		parts := bareKey.FindStringSubmatch(match)
		if bareKeySubcommands[strings.ToLower(parts[3])] {
			return match
		}
		return parts[1] + parts[2] + "[REDACTED]"
	})
}

// Quoted fields also occur inside diagnostic prose, outside a JSON document.
var quotedSecret = regexp.MustCompile(`(?i)("(?:password|passwd|secret|community|token|access[_-]token|refresh[_-]token|api[_-]key|client[_-]secret|private[_-]key)"\s*:\s*)("(?:\\.|[^"\\])*"|[^\s,}]+)`)

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	switch key {
	case "password", "passwd", "encryptedpassword", "secret", "community", "token", "accesstoken", "refreshtoken", "apikey", "clientsecret", "privatekey", "authorization", "proxyauthorization", "authenticationkey", "authenticationpassword", "authkey", "md5key", "keystring", "presharedkey", "privacykey", "privacypassword":
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
	value = redactBareKey(value)
	for _, pattern := range sensitivePatterns {
		value = pattern.ReplaceAllString(value, "$1$2[REDACTED]")
	}
	return value
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
