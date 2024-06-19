package auth

import (
	"errors"
	"fmt"
	"github.com/markbates/goth/gothic"
	"net/http"
)

const (
	ProviderGoogle = "google"
	ProviderUnsafe = "unsafe"
)

// AuthorizedProviderUserData represents authorized user data from a provider
// it can be used to create an account or link to an existing one
type AuthorizedProviderUserData struct {
	Provider string
	Email    string
	UserID   string
	Name     string
}

func AuthenticateAndGetAuthorizedUserData(request *http.Request, writer http.ResponseWriter, filters []Filter) (*AuthorizedProviderUserData, error) {
	provider := request.URL.Query().Get("provider")

	var user AuthorizedProviderUserData

	if provider == "" {
		return nil, errors.New("provider must not be empty")
	}

	switch provider {
	case ProviderGoogle:
		gothUser, err := gothic.CompleteUserAuth(writer, request)
		if err != nil {
			return nil, err
		}

		user.UserID = gothUser.UserID
		user.Email = gothUser.Email
		user.Name = gothUser.Name
	case ProviderUnsafe:
		username := request.URL.Query().Get("username")
		if username == "" {
			writer.Write([]byte("unauthorized"))
		}

		user.Email = fmt.Sprintf("%s@example.com", username)
		user.UserID = username
		user.Name = username
	}

	user.Provider = provider

	for _, filter := range filters {
		if !filter.Validate(user) {
			return nil, fmt.Errorf("user %s failed filter %s", user.UserID, filter.Name())
		}
	}

	return &user, nil
}
