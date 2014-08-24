package simplessh

import (
	"code.google.com/p/go.crypto/ssh"
	"github.com/pkg/sftp"

	"io"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
)

type Client struct {
	SSHClient *ssh.Client
}

func ConnectWithPassword(host, username, pass string) (*Client, error) {
	authMethod := ssh.Password(pass)

	return connect(username, host, authMethod)
}

// Connect with a private key. If privKeyPath is an empty string it will attempt
// to use $HOME/.ssh/id_rsa.
func ConnectWithKeyFile(host, username, privKeyPath string) (*Client, error) {
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

	return ConnectWithKey(host, username, string(privKey))
}

// Connect with a private key.
func ConnectWithKey(host, username, privKey string) (*Client, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privKey))
	if err != nil {
		return nil, err
	}

	authMethod := ssh.PublicKeys(signer)

	return connect(username, host, authMethod)
}

func connect(username, host string, authMethod ssh.AuthMethod) (*Client, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{authMethod},
	}

	host = addPortToHost(host)

	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return nil, err
	}

	c := &Client{SSHClient: client}
	return c, nil
}

func (c *Client) Exec(cmd string) ([]byte, error) {
	session, err := c.SSHClient.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	return session.CombinedOutput(cmd)
}

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

func addPortToHost(host string) string {
	_, _, err := net.SplitHostPort(host)

	// We got an error so blindly try to add a port number
	if err != nil {
		return net.JoinHostPort(host, "22")
	}

	return host
}
