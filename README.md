# simplessh
[![GoDoc](https://godoc.org/github.com/sfreiberg/simplessh?status.png)](https://godoc.org/github.com/sfreiberg/simplessh)

SimpleSSH is a simple wrapper around go ssh and sftp libraries.
Altered to add support for `diffie-hellman-group1-sha1` and `diffie-hellman-group14-sha1`.

[RFC 4253](https://www.rfc-editor.org/rfc/rfc4253)
```
8.1.  diffie-hellman-group1-sha1

   The "diffie-hellman-group1-sha1" method specifies the Diffie-Hellman
   key exchange with SHA-1 as HASH, and Oakley Group 2 [RFC2409] (1024-
   bit MODP Group).  This method MUST be supported for interoperability
   as all of the known implementations currently support it.  Note that
   this method is named using the phrase "group1", even though it
   specifies the use of Oakley Group 2.

8.2.  diffie-hellman-group14-sha1

   The "diffie-hellman-group14-sha1" method specifies a Diffie-Hellman
   key exchange with SHA-1 as HASH and Oakley Group 14 [RFC3526] (2048-
   bit MODP Group), and it MUST also be supported.
```

## Features
* Multiple authentication methods (password, private key and ssh-agent)
* Sudo support
* Simple file upload/download support

## Installation
`go get github.com/sfreiberg/simplessh`

## Example

```
package main

import (
	"fmt"
	
	"github.com/sfreiberg/simplessh"
)

func main() {
	/*
		Leave privKeyPath empty to use $HOME/.ssh/id_rsa.
		If username is blank simplessh will attempt to use the current user.
	*/
	client, err := simplessh.ConnectWithKeyFile("localhost:22", "root", "/home/user/.ssh/id_rsa")
	if err != nil {
		panic(err)
	}
	defer client.Close()

	output, err := client.Exec("uptime")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Uptime: %s\n", output)
}

```

## License
SimpleSSH is licensed under the MIT license.
