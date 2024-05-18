package readable

import (
	"testing"
)

func TestNewToken(t *testing.T) {
	// create a new token and inspect it

	tok := NewToken()

	if tok.String()[0:4] != "tok-" {
		t.Error("expected token to be of the format tok-*")
	}
}

func TestNewTokenFromString(t *testing.T) {
	stringVersion := "tok-a41dc339-418f-46ba-b5f9-13d17a90390e"

	tok, err := NewTokenFromString(stringVersion)

	if err != nil {
		t.Error("unexpected error creating token", err)
	}

	if tok.String() != stringVersion {
		t.Errorf("unexpected format for token got %s wanted %s", tok.String(), stringVersion)
	}
}
