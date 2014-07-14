simplessh
=========

SimpleSSH is a simple wrapper around 

License
=======

SimpleSSH is licensed under the MIT license.

Installation
============
`go get github.com/sfreiberg/simplessh`

Documentation
=============
[GoDoc](http://godoc.org/github.com/sfreiberg/simplessh)

Example
=======

```
package main

import (
	"github.com/sfreiberg/simplessh"

	"fmt"
)

func main() {
	client, err := simplessh.ConnectWithPrivateKey("localhost:22", "root", "/home/user/.ssh/id_rsa")
	if err != nil {
		panic(err)
	}

	output, err := client.Exec("uptime")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Uptime: %s\n", output)
}

```