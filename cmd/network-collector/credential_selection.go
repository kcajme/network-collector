package main

import "strings"

// Auto-prompt only for environment-backed credentials in a real terminal.
// Enterprise/file providers must retain their own configuration and errors.
func selectCredentialProvider(configured string, forcePrompt, terminal bool, username, password string) string {
	provider := strings.ToLower(strings.TrimSpace(configured))
	if forcePrompt {
		return "interactive"
	}
	if terminal && (provider == "" || provider == "env" || provider == "environment") &&
		(strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "") {
		return "interactive"
	}
	return provider
}
