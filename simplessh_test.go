package simplessh

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
)

// newTestSFTPClient returns an sftp client connected to an in-process server
// that serves the local filesystem.
func newTestSFTPClient(t *testing.T) *sftp.Client {
	t.Helper()

	cr, sw := io.Pipe()
	sr, cw := io.Pipe()

	server, err := sftp.NewServer(struct {
		io.Reader
		io.WriteCloser
	}{sr, sw})
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve()

	client, err := sftp.NewClientPipe(cr, cw)
	if err != nil {
		t.Fatal(err)
	}
	// Close the server first so the client's receive loop sees EOF,
	// otherwise client.Close blocks forever.
	t.Cleanup(func() {
		server.Close()
		client.Close()
	})

	return client
}

func writeFile(t *testing.T, name, data string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, perm); err != nil {
		t.Fatal(err)
	}
}

func TestUploadDir(t *testing.T) {
	local := t.TempDir()
	writeFile(t, filepath.Join(local, "a.txt"), "a", 0644)
	writeFile(t, filepath.Join(local, "sub", "b.txt"), "b", 0600)
	writeFile(t, filepath.Join(local, "sub", "deeper", "run.sh"), "#!/bin/sh\n", 0755)
	if err := os.Mkdir(filepath.Join(local, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(local, "a.txt"), filepath.Join(local, "link")); err != nil {
		t.Fatal(err)
	}

	// Upload into a directory that doesn't exist yet
	remote := filepath.Join(t.TempDir(), "dest", "nested")
	if err := uploadDir(newTestSFTPClient(t), local, filepath.ToSlash(remote)); err != nil {
		t.Fatal(err)
	}

	files := []struct {
		name string
		data string
		perm os.FileMode
	}{
		{"a.txt", "a", 0644},
		{"sub/b.txt", "b", 0600},
		{"sub/deeper/run.sh", "#!/bin/sh\n", 0755},
	}
	for _, f := range files {
		name := filepath.Join(remote, filepath.FromSlash(f.name))
		data, err := os.ReadFile(name)
		if err != nil {
			t.Errorf("%s: %v", f.name, err)
			continue
		}
		if string(data) != f.data {
			t.Errorf("%s: got %q, want %q", f.name, data, f.data)
		}
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != f.perm {
			t.Errorf("%s: got mode %v, want %v", f.name, info.Mode().Perm(), f.perm)
		}
	}

	info, err := os.Stat(filepath.Join(remote, "empty"))
	if err != nil {
		t.Fatalf("empty dir not created: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Errorf("empty: got %v, want dir with mode 0700", info.Mode())
	}

	if _, err := os.Lstat(filepath.Join(remote, "link")); !os.IsNotExist(err) {
		t.Errorf("symlink should be skipped, got err %v", err)
	}
}

func TestUploadDirMissingLocal(t *testing.T) {
	err := uploadDir(newTestSFTPClient(t), filepath.Join(t.TempDir(), "missing"), t.TempDir())
	if !os.IsNotExist(err) {
		t.Fatalf("got %v, want not exist error", err)
	}
}
