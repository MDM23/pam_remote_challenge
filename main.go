package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/MDM23/pam_remote_challenge/pam"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	keyPem, err := ioutil.ReadFile("snakeoil.pem")
	if err != nil {
		log.Fatalf("read key: %s", err)
	}

	block, _ := pem.Decode(keyPem)
	if block == nil {
		log.Fatalln("bad PEM data!")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("parse key: %s", err)
	}

	challenge, err := pam.NewAuthChallenge(key)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Print(challenge, "\nEnter PIN code to continue: ")

	pin, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println()

	if challenge.PINMatches(string(pin)) {
		os.Exit(0)
	}

	time.Sleep(3 * time.Second)
	fmt.Println("Authentication failed!")
	os.Exit(1)
}
