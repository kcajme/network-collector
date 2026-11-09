package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func TestConfirmationAcrossRealSSHTransport(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &cryptossh.ServerConfig{PasswordCallback: func(cryptossh.ConnMetadata, []byte) (*cryptossh.Permissions, error) { return nil, nil }}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		server, channels, requests, err := cryptossh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go cryptossh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			go func() {
				for request := range requests {
					request.Reply(true, nil)
					if request.Type == "shell" {
						io.WriteString(channel, "router#")
					}
				}
			}()
			var command strings.Builder
			var last byte
			for {
				var b [1]byte
				if _, err := channel.Read(b[:]); err != nil {
					return
				}
				if b[0] != '\r' && b[0] != '\n' {
					channel.Write(b[:])
					command.WriteByte(b[0])
					last = b[0]
					continue
				}
				if b[0] == '\n' && last == '\r' {
					last = b[0]
					continue
				}
				last = b[0]
				line := command.String()
				command.Reset()
				io.WriteString(channel, "\r\n")
				switch {
				case strings.HasPrefix(line, "install activate"):
					io.WriteString(channel, "This install operation will reload the system, continue? [yes/no]:")
				case line == "yes":
					received <- line
					channel.Close()
					return
				default:
					io.WriteString(channel, "router#")
				}
			}
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	client := NewClient(WithPort(address.Port), WithHostKeyPolicy("insecure", ""), WithConnectionTimeout(5*time.Second), WithOperationTimeout(3*time.Second))
	if err := client.Connect(address.IP.String(), "testuser", "testpass", "cisco_iosxr"); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	started := time.Now()
	output, err := client.ExecuteWithConfirmation("install activate id 58 sync", `continue\?`, "yes", false)
	if err != nil || !strings.Contains(output, "continue?") {
		t.Fatalf("confirmation failed: %q %v", output, err)
	}
	// Match the workflow: close immediately after sending the reboot answer.
	_ = client.Close()
	select {
	case response := <-received:
		if response != "yes" {
			t.Fatal(response)
		}
	case <-time.After(time.Second):
		t.Fatal("router never received confirmation")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("confirmation waited for a router prompt after answering")
	}
}
