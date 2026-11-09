package ssh

import (
	"context"
	"errors"
	"fmt"
	"github.com/scrapli/scrapligo/util"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/scrapli/scrapligo/driver/opoptions"
)

type confirmationSession interface {
	SendUntilPrompt(string, *regexp.Regexp) ([]byte, error)
	SendConfirmation(string, bool) ([]byte, error)
}

func (s *scrapligoSSHSession) SendUntilPrompt(command string, prompt *regexp.Regexp) ([]byte, error) {
	return s.driver.Channel.SendInput(command, opoptions.WithInterimPromptPattern([]*regexp.Regexp{prompt}), opoptions.WithNoStripPrompt())
}

func (s *scrapligoSSHSession) SendConfirmation(response string, waitForPrompt bool) ([]byte, error) {
	if waitForPrompt {
		return s.driver.Channel.SendInput(response)
	}
	// Reboot confirmations may not echo their answer or return a normal prompt.
	// Send exactly one response and newline; skip logout hooks on this session.
	if err := s.driver.Channel.WriteAndReturn([]byte(response), false); err != nil {
		return nil, err
	}
	s.reloadExpected = true
	ctx, cancel := context.WithTimeout(context.Background(), s.driver.Channel.GetTimeout(0))
	defer cancel()
	ack := regexp.MustCompile(regexp.QuoteMeta(response) + `\r?\n`)
	var output []byte
	for {
		select {
		case <-ctx.Done():
			return output, fmt.Errorf("confirmation delivery was not acknowledged: %w", ctx.Err())
		default:
		}
		chunk, err := s.driver.Channel.Read()
		if err != nil {
			if errors.Is(err, util.ErrConnectionError) || errors.Is(err, io.EOF) {
				return output, nil
			}
			return output, err
		}
		if len(chunk) > maxSSHResponseBytes-len(output) {
			return nil, fmt.Errorf("SSH response exceeds the %d-byte limit", maxSSHResponseBytes)
		}
		start := max(0, len(output)-len(response)-8)
		output = append(output, chunk...)
		if ack.Match(output[start:]) {
			return output, nil
		}
		if len(chunk) == 0 {
			time.Sleep(s.driver.Channel.ReadDelay)
		}
	}

}

func (c *Client) ExecuteWithConfirmation(command, prompt, response string, waitForPrompt bool) (string, error) {
	if c == nil || c.network == nil {
		return "", fmt.Errorf("SSH client is not connected")
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("command is required")
	}
	re, err := regexp.Compile(prompt)
	if err != nil || strings.TrimSpace(prompt) == "" || re.MatchString("") {
		return "", fmt.Errorf("invalid confirmation prompt regex")
	}
	switch response {
	case "yes", "no", "y", "n":
	default:
		return "", fmt.Errorf("confirmation response must be yes, no, y, or n")
	}
	session, ok := c.network.(confirmationSession)
	if !ok {
		return "", fmt.Errorf("SSH session does not support confirmation prompts")
	}
	output, err := session.SendUntilPrompt(command, re)
	if len(output) > maxSSHResponseBytes {
		return "", fmt.Errorf("SSH response exceeds the %d-byte limit", maxSSHResponseBytes)
	}
	if err != nil {
		return string(output), fmt.Errorf("waiting for confirmation prompt: %w", err)
	}
	if !re.Match(output) {
		return string(output), fmt.Errorf("expected confirmation prompt not received; response was not sent")
	}
	answer, err := session.SendConfirmation(response, waitForPrompt)
	if len(answer) > maxSSHResponseBytes-len(output) {
		return "", fmt.Errorf("SSH response exceeds the %d-byte limit", maxSSHResponseBytes)
	}
	transcript := string(output) + "\n[confirmation response: " + response + "]\n" + string(answer)
	if len(transcript) > maxSSHResponseBytes {
		return "", fmt.Errorf("SSH response exceeds the %d-byte limit", maxSSHResponseBytes)
	}
	if err != nil {
		return transcript, fmt.Errorf("sending confirmation response: %w", err)
	}
	return transcript, nil
}
