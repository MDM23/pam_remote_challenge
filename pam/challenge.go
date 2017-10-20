package pam

import (
	"bytes"
	cRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/ascii85"
	"math"
	"math/rand"
	"strconv"
)

// AuthChallenge holds data for a single authentication attempt
type AuthChallenge struct {
	plainPIN     string
	encryptedPIN []byte
}

// NewAuthChallenge creates a new instance of AuthChallenge. The passed private
// key is used to encrypt a random PIN code.
func NewAuthChallenge(privateKey *rsa.PrivateKey) (*AuthChallenge, error) {
	c := &AuthChallenge{plainPIN: makeRandomPIN(10)}

	encoded, err := rsa.EncryptOAEP(
		sha1.New(),
		cRand.Reader,
		&privateKey.PublicKey,
		[]byte(c.plainPIN),
		[]byte(""),
	)

	if err != nil {
		return nil, err
	}

	c.encryptedPIN = encoded
	return c, nil
}

// PINMatches compares the given PIN against the random PIN that was generated
// int NewAuthChallenge().
func (c AuthChallenge) PINMatches(pin string) bool {
	return pin == c.plainPIN
}

// String returns the decrypted PIN of an AuthChallenge instance  as an
// ASCII85-encoded string.
func (c AuthChallenge) String() string {
	out := " ---- AUTHENTICATION CHALLENGE ----\n"

	buffer := make([]byte, ascii85.MaxEncodedLen(len(c.encryptedPIN)))
	n := ascii85.Encode(buffer, c.encryptedPIN)
	buffer = buffer[0:n]

	line := ""

	runes := bytes.Runes(buffer)
	l := len(runes)

	for i, r := range runes {
		line += string(r)
		if (i+1)%32 == 0 {
			out += "| " + padRight(line, 32) + " |\n"
			line = ""
		} else if (i + 1) == l {
			out += "| " + padRight(line, 32) + " |\n"
		}
	}

	return out + " ----------------------------------"
}

func makeRandomPIN(length int) string {
	max := int64(math.Pow10(length) - 1)
	min := int64(math.Pow10(length-1) * 9)
	return strconv.FormatInt(max-rand.Int63n(min), 10)
}

func padRight(s string, length int) string {
	l := length - len(s)

	for i := 0; i < l; i++ {
		s += " "
	}

	return s
}
