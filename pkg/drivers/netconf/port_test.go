package netconf

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNETCONFPortAndSubsystemReachSystemSSH(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "argv")
	script := "#!/bin/sh\n[ \"$1\" = -Q ] && exit 1\nprintf '%s\\n' \"$@\" > \"$SSH_TEST_CAPTURE\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_TEST_CAPTURE", capture)
	for _, port := range []int{0, 22, 1830} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			_ = os.Remove(capture)
			client := &ScrapligoNETCONF{}
			err := client.Connect("192.0.2.1", "testuser", "testpass", WithPort(port), WithNetconfTimeouts(time.Second, time.Second), WithHostKeyPolicy("insecure", ""))
			if err == nil {
				t.Fatal("fake ssh unexpectedly connected")
			}
			content, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			expected := port
			if expected == 0 {
				expected = 830
			}
			args := string(content)
			if !strings.Contains(args, "-p\n"+strconv.Itoa(expected)+"\n") || !strings.Contains(args, "-s\nnetconf\n") {
				t.Fatalf("wrong SSH port or subsystem: %q", args)
			}
		})
	}
}

func TestNETCONFRejectsInvalidPortBeforeTransport(t *testing.T) {
	for _, port := range []int{-1, 65536} {
		client := &ScrapligoNETCONF{}
		err := client.Connect("192.0.2.1", "testuser", "testpass", WithPort(port))
		if err == nil || !strings.Contains(err.Error(), "NETCONF port") {
			t.Fatalf("port %d: %v", port, err)
		}
	}
}
