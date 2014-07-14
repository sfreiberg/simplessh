package simplessh

import (
	"code.google.com/p/go.crypto/ssh"
	"github.com/pkg/sftp"

	"io"
	"io/ioutil"
	"os"
)

type Client struct {
	SSHClient *ssh.Client
}

func ConnectWithPassword(host, user, pass string) (*Client, error) {
	authMethod := ssh.Password(pass)

	return connect(user, host, authMethod)
}

func ConnectWithPrivateKey(host, user, privKeyPath string) (*Client, error) {
	privKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	authMethod := ssh.PublicKeys(signer)

	return connect(user, host, authMethod)
}

func connect(user, host string, authMethod ssh.AuthMethod) (*Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{authMethod},
	}

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
