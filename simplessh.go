package simplessh

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const DefaultTimeout = 30 * time.Second

// This is the phrase that tells us sudo is looking for a password via stdin
const sudoPwPrompt = "sudo_password"

// Set a default HostKeyCallback variable. This may not be desireable for some
// environments.
var HostKeyCallback = ssh.InsecureIgnoreHostKey()

// sudoWriter is used to both combine stdout and stderr as well as
// look for a password request from sudo.
type sudoWriter struct {
	b     bytes.Buffer
	pw    string    // The password to pass to sudo (if requested)
	stdin io.Writer // The writer from the ssh session
	m     sync.Mutex
}

func (w *sudoWriter) Write(p []byte) (int, error) {
	// If we get the sudo password prompt phrase send the password via stdin
	// and don't write it to the buffer.
	if string(p) == sudoPwPrompt {
		w.stdin.Write([]byte(w.pw + "\n"))
		w.pw = "" // We don't need the password anymore so reset the string
		return len(p), nil
	}

	w.m.Lock()
	defer w.m.Unlock()

	return w.b.Write(p)
}

type Client struct {
	SSHClient *ssh.Client
}

// Connect with a password. If username is empty simplessh will attempt to get the current user.
func ConnectWithPassword(host, username, pass string) (*Client, error) {
	return ConnectWithPasswordTimeout(host, username, pass, DefaultTimeout)
}

// Same as ConnectWithPassword but allows a custom timeout. If username is empty simplessh will attempt to get the current user.
func ConnectWithPasswordTimeout(host, username, pass string, timeout time.Duration) (*Client, error) {
	authMethod := ssh.Password(pass)

	return connect(username, host, authMethod, timeout)
}

// Connect with a private key. If privKeyPath is an empty string it will attempt
// to use $HOME/.ssh/id_rsa. If username is empty simplessh will attempt to get the current user.
func ConnectWithKeyFileTimeout(host, username, privKeyPath string, timeout time.Duration) (*Client, error) {
	if privKeyPath == "" {
		currentUser, err := user.Current()
		if err == nil {
			privKeyPath = filepath.Join(currentUser.HomeDir, ".ssh", "id_rsa")
		}
	}

	privKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}

	return ConnectWithKeyTimeout(host, username, string(privKey), timeout)
}

// Connect with a private key with passphrase. If privKeyPath is an empty string it will attempt
// to use $HOME/.ssh/id_rsa. If username is empty simplessh will attempt to get the current user.
func ConnectWithKeyFilePassphraseTimeout(host, username, privKeyPath string, passPhrase string, timeout time.Duration) (*Client, error) {
	if privKeyPath == "" {
		currentUser, err := user.Current()
		if err == nil {
			privKeyPath = filepath.Join(currentUser.HomeDir, ".ssh", "id_rsa")
		}
	}
	pemKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemKey, []byte(passPhrase))
	if err != nil {
		return nil, err
	}

	return ConnectWithKeyPassphraseTimeout(host, username, signer, timeout)
}

// Same as ConnectWithKeyFile but allows a custom timeout. If username is empty simplessh will attempt to get the current user.
func ConnectWithKeyFile(host, username, privKeyPath string) (*Client, error) {
	return ConnectWithKeyFileTimeout(host, username, privKeyPath, DefaultTimeout)
}

// KeyFile with a passphrase
func ConnectWithKeyFilePassphrase(host, username, privKeyPath string, passPhrase string) (*Client, error) {
	return ConnectWithKeyFilePassphraseTimeout(host, username, privKeyPath, passPhrase, DefaultTimeout)
}

// Connect with a private key with a custom timeout. If username is empty simplessh will attempt to get the current user.
func ConnectWithKeyTimeout(host, username, privKey string, timeout time.Duration) (*Client, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privKey))
	if err != nil {
		return nil, err
	}

	authMethod := ssh.PublicKeys(signer)

	return connect(username, host, authMethod, timeout)
}

// Connect with a private key with passphrase with a custom timeout. If username is empty simplessh will attempt to get the current user.
func ConnectWithKeyPassphraseTimeout(host, username string, signer ssh.Signer, timeout time.Duration) (*Client, error) {
	authMethod := ssh.PublicKeys(signer)

	return connect(username, host, authMethod, timeout)
}

// Connect with a private key. If username is empty simplessh will attempt to get the current user.
func ConnectWithKey(host, username, privKey string) (*Client, error) {
	return ConnectWithKeyTimeout(host, username, privKey, DefaultTimeout)
}

// Connect to an ssh agent with a custom timeout. If username is empty simplessh will attempt to get the current user. The windows implementation uses a different library which expects pageant to be running.
func ConnectWithAgentTimeout(host, username string, timeout time.Duration) (*Client, error) {
	return connectWithAgentTimeout(host, username, timeout)
}

// Connect to an ssh agent. If username is empty simplessh will attempt to get the current user. The windows implementation uses a different library which expects pageant to be running.
func ConnectWithAgent(host, username string) (*Client, error) {
	return ConnectWithAgentTimeout(host, username, DefaultTimeout)
}

func connect(username, host string, authMethod ssh.AuthMethod, timeout time.Duration) (*Client, error) {
	if username == "" {
		user, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("Username wasn't specified and couldn't get current user: %v", err)
		}

		username = user.Username
	}

	sshconf := ssh.Config{
		Ciphers: []string{
			"arcfour128",
			"arcfour256",
			"arcfour",
			"aes128-ctr",
			"aes192-ctr",
			"aes256-ctr",
			"aes128-cbc",
			"3des-cbc",
			"des-cbc",

			"aes128-gcm@openssh.com",
			"chacha20-poly1305@openssh.com",
		},
		KeyExchanges: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"diffie-hellman-group-exchange-sha1",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group1-sha1",
			"diffie-hellman-group14-sha1",
			"diffie-hellman-group-sha256",
			"rsa-sha2-512",
			"rsa-sha2-256",
			"ssh-rsa",
		},
	}

	config := &ssh.ClientConfig{
		Config:          sshconf,
		User:            username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: HostKeyCallback,
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoDSA,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoSKECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoSKED25519,
			ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoRSASHA512,

			ssh.CertAlgoRSAv01,
			ssh.CertAlgoDSAv01,
			ssh.CertAlgoECDSA256v01,
			ssh.CertAlgoECDSA384v01,
			ssh.CertAlgoECDSA521v01,
			ssh.CertAlgoSKECDSA256v01,
			ssh.CertAlgoED25519v01,
			ssh.CertAlgoSKED25519v01,
			ssh.CertAlgoRSASHA256v01,
			ssh.CertAlgoRSASHA512v01,
		},
	}

	host = addPortToHost(host)

	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(sshConn, chans, reqs)

	c := &Client{SSHClient: client}
	return c, nil
}

// Execute an array of commands within the same shell and return stderr and stdout
func (c *Client) ExecMulti(cmd []string) (string, error) {
	session, err := c.SSHClient.NewSession()
	if err != nil {
		return "error", err
	}
	
	defer session.Close()
	
	w, err := session.StdinPipe()
	if err != nil {
		return "error", err
	}
	
	stdout, err := session.StdoutPipe()
	if err != nil {
		return "error", nil
	}
	
	err = session.Shell()
	for i, _ := range cmd {
		// go io.Copy(w, fmt.Sprintf("%s\n", cmd[i]))
		w.Write([]byte(fmt.Sprintf("%s\n", cmd[i])))
		go io.Copy(os.Stdout, stdout)
	}
	return "finished executing multiple commands", nil
}

// Execute cmd on the remote host and return stderr and stdout
func (c *Client) Exec(cmd string) ([]byte, error) {
	session, err := c.SSHClient.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	return session.CombinedOutput(cmd)
}

// Execute cmd via sudo. Do not include the sudo command in
// the cmd string. For example: Client.ExecSudo("uptime", "password").
// If you are using passwordless sudo you can use the regular Exec()
// function.
func (c *Client) ExecSudo(cmd, passwd string) ([]byte, error) {
	session, err := c.SSHClient.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	// -n run non interactively
	// -p specify the prompt. We do this to know that sudo is asking for a passwd
	// -S Writes the prompt to StdErr and reads the password from StdIn
	cmd = "sudo -p " + sudoPwPrompt + " -S " + cmd

	// Use the sudoRW struct to handle the interaction with sudo and capture the
	// output of the command
	w := &sudoWriter{
		pw: passwd,
	}
	w.stdin, err = session.StdinPipe()
	if err != nil {
		return nil, err
	}

	// Combine stdout, stderr to the same writer which also looks for the sudo
	// password prompt
	session.Stdout = w
	session.Stderr = w

	err = session.Run(cmd)

	return w.b.Bytes(), err
}

// Download a file from the remote server
func (c *Client) Download(remote, local string) error {
	client, err := sftp.NewClient(c.SSHClient)
	if err != nil {
		return err
	}
	defer client.Close()

	remoteFile, err := client.Open(remote)
	if err != nil {
		return err
	}
	defer remoteFile.Close()

	localFile, err := os.Create(local)
	if err != nil {
		return err
	}
	defer localFile.Close()

	_, err = io.Copy(localFile, remoteFile)
	return err
}

// Upload a file to the remote server
func (c *Client) Upload(local, remote string) error {
	client, err := sftp.NewClient(c.SSHClient)
	if err != nil {
		return err
	}
	defer client.Close()

	localFile, err := os.Open(local)
	if err != nil {
		return err
	}
	defer localFile.Close()

	remoteFile, err := client.Create(remote)
	if err != nil {
		return err
	}

	_, err = io.Copy(remoteFile, localFile)
	return err
}

// Remove a file from the remote server
func (c *Client) Remove(path string) error {
	client, err := sftp.NewClient(c.SSHClient)
	if err != nil {
		return err
	}
	defer client.Close()

	return client.Remove(path)
}

// Remove a directory from the remote server
func (c *Client) RemoveDirectory(path string) error {
	client, err := sftp.NewClient(c.SSHClient)
	if err != nil {
		return err
	}
	defer client.Close()

	return client.RemoveDirectory(path)
}

// Read a remote file and return the contents.
func (c *Client) ReadAll(filepath string) ([]byte, error) {
	sftp, err := c.SFTPClient()
	if err != nil {
		panic(err)
	}
	defer sftp.Close()

	file, err := sftp.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ioutil.ReadAll(file)
}

// Close the underlying SSH connection
func (c *Client) Close() error {
	return c.SSHClient.Close()
}

// Return an sftp client. The client needs to be closed when it's no
// longer needed.
func (c *Client) SFTPClient() (*sftp.Client, error) {
	return sftp.NewClient(c.SSHClient)
}

func addPortToHost(host string) string {
	_, _, err := net.SplitHostPort(host)

	// We got an error so blindly try to add a port number
	if err != nil {
		return net.JoinHostPort(host, "22")
	}

	return host
}
