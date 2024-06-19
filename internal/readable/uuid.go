package readable

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
)

// UUID is a readable uuid, types which implement this interface should ensure they have a unique prefix based on their type
type UUID interface {
	String() string
}

// Token is an auth token for authenticating with the auth proxy
type Token struct {
	uuid uuid.UUID
}

// NewToken generates a new readable token
func NewToken() Token {
	var tok Token

	tok.uuid = uuid.New()

	return tok
}

func NewTokenFromString(token string) (*Token, error) {
	var tok Token

	if token[0:4] != "tok-" {
		return nil, errors.New("tokens must start with tok-, token is invalid")
	} else {
		uuid, err := uuid.Parse(token[4:])
		if err != nil {
			return nil, err
		}
		tok.uuid = uuid
	}

	return &tok, nil
}

// UserID ...
type UserID struct {
	uuid uuid.UUID
}

// NewToken generates a new readable token
func NewUserID() UserID {
	var tok UserID

	tok.uuid = uuid.New()

	return tok
}

func NewUserIDFromString(token string) (*UserID, error) {
	var tok UserID

	if token[0:4] != "usr-" {
		return nil, errors.New("user ids must start with usr-, token is invalid")
	} else {
		uuid, err := uuid.Parse(token[4:])
		if err != nil {
			return nil, err
		}
		tok.uuid = uuid
	}

	return &tok, nil
}

func (t *UserID) String() string {
	return fmt.Sprintf("usr-%s", t.uuid.String())
}

func (t *Token) String() string {
	return fmt.Sprintf("tok-%s", t.uuid.String())
}

var _ UUID = (*Token)(nil)
var _ UUID = (*UserID)(nil)
