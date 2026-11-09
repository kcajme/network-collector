package ssh

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

type fakeConfirmationSession struct {
	fakeSSHSession
	output    []byte
	promptErr error
	replyErr  error
	replies   []string
	wait      bool
}

func (s *fakeConfirmationSession) SendUntilPrompt(_ string, _ *regexp.Regexp) ([]byte, error) {
	return s.output, s.promptErr
}
func (s *fakeConfirmationSession) SendConfirmation(reply string, wait bool) ([]byte, error) {
	s.replies = append(s.replies, reply)
	s.wait = wait
	return []byte("router#"), s.replyErr
}

func TestConfirmationOnlyAnswersVerifiedQuestion(t *testing.T) {
	for _, mode := range []string{"reload", "normal", "mismatch", "timeout", "send-error", "invalid-pattern", "invalid-response"} {
		t.Run(mode, func(t *testing.T) {
			session := &fakeConfirmationSession{output: []byte("This install operation will reload the system, continue? [yes/no]:")}
			client := NewClient()
			client.network = session
			pattern := `continue\?`
			reply := "yes"
			wait := mode == "normal"
			switch mode {
			case "mismatch":
				session.output = []byte("operation rejected\nrouter#")
			case "timeout":
				session.promptErr = errors.New("timed out")
			case "send-error":
				session.replyErr = errors.New("closed")
			case "invalid-pattern":
				pattern = "["
			case "invalid-response":
				reply = "yes\nreload"
			}
			output, err := client.ExecuteWithConfirmation("install activate id 58 sync", pattern, reply, wait)
			success := mode == "reload" || mode == "normal"
			if success && (err != nil || len(session.replies) != 1 || session.replies[0] != "yes" || session.wait != wait || !strings.Contains(output, "continue?")) {
				t.Fatalf("exchange failed: %s %v", output, err)
			}
			if !success && err == nil {
				t.Fatal("confirmation error ignored")
			}
			if !success && mode != "send-error" && len(session.replies) != 0 {
				t.Fatal("answered an absent or invalid question")
			}
		})
	}
}
