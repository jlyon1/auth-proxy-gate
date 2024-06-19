package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
)

// LinkState represents the state that will be passed through an auth provider to do the actual account linking
// it will be passed as the query param 'state'
type LinkState struct {
	Link      bool   `json:"Link,omitempty"`
	AccountId string `json:"AccountId"`
	Rand      []byte `json:"Rand,omitempty"`
}

// randomize generates some random bytes to increase randomness
func (l *LinkState) randomize() {
	nonceBytes := make([]byte, 50)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("gothic: source of randomness unavailable: " + err.Error())
	}
	l.Rand = nonceBytes
}

// Encode encodes this state object as a base64 encoded string
func (l *LinkState) Encode() (string, error) {
	l.randomize()

	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	err := json.NewEncoder(encoder).Encode(l)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// DecodeLinkStateFromStateVar decodes the string into the state object
func DecodeLinkStateFromStateVar(source string) (*LinkState, error) {
	var s LinkState
	err := json.NewDecoder(base64.NewDecoder(base64.StdEncoding, strings.NewReader(source))).Decode(&s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
