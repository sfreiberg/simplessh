package simplessh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// listen returns a TCP listener on localhost that is closed when the test ends.
func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// startSSHServer runs a minimal in-process SSH server that accepts any
// client, opens sessions but rejects every request on them (so exec and the
// sftp subsystem fail).
func startSSHServer(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	ln := listen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					conn.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, chReqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range chReqs {
							req.Reply(false, nil)
						}
						ch.Close()
					}()
				}
			}()
		}
	}()

	return ln.Addr().String()
}

func TestConnectHandshakeTimeout(t *testing.T) {
	// A server that accepts the TCP connection but never speaks SSH.
	ln := listen(t)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		<-done
		conn.Close()
	}()

	errc := make(chan error, 1)
	go func() {
		_, err := ConnectWithPasswordTimeout(ln.Addr().String(), "user", "pass", 200*time.Millisecond)
		errc <- err
	}()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("connect to a silent server: expected an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connect did not return; the timeout doesn't cover the SSH handshake")
	}
}

func TestReadAllSFTPUnavailable(t *testing.T) {
	addr := startSSHServer(t)
	client, err := ConnectWithPassword(addr, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The server rejects the sftp subsystem; ReadAll used to panic here.
	if _, err := client.ReadAll("/etc/hostname"); err == nil {
		t.Fatal("ReadAll without an sftp subsystem: expected an error")
	}
}
