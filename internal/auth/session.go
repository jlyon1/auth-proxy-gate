package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/readable"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/users"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strings"
)

const (
	InternalId = "internal_id"
)

var log *zap.SugaredLogger

func init() {
	logger, _ := zap.NewDevelopment()
	log = logger.Sugar()
}

type UserSessionManager struct {
	DB *sql.DB
}

func (a *UserSessionManager) Shutdown() {
	a.DB.Close()
}

type AuthenticatorConfig struct {
	MaxAge             int    `json:"MaxAge,omitempty"`
	HttpOnly           bool   `json:"HttpOnly,omitempty"`
	Secure             bool   `json:"Secure,omitempty"`
	SecretKey          string `json:"SecretKey"`
	DBConnectionString string `json:"DBConnectionString,omitempty"`
	ProviderConfigs    []struct {
		ProviderName string `json:"ProviderName,omitempty"`
		ClientID     string `json:"ClientID,omitempty"`
		ClientSecret string `json:"ClientSecret,omitempty"`
		RedirectUri  string `json:"RedirectUri,omitempty"`
		Scopes       string `json:"Scopes"`
	} `json:"ProviderConfigs,omitempty"`
}

func NewAuthenticator(config AuthenticatorConfig) (*UserSessionManager, error) {
	store := sessions.NewCookieStore([]byte(config.SecretKey))
	store.MaxAge(config.MaxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = config.Secure

	gothic.Store = store

	db, err := sql.Open("sqlite3", "./accounts.db")
	if err != nil {
		panic(err)
	}

	var a UserSessionManager

	var providers []goth.Provider

	for _, provider := range config.ProviderConfigs {
		switch provider.ProviderName {
		case ProviderGoogle:
			prov := google.New(provider.ClientID, provider.ClientSecret, fmt.Sprintf("%s/auth/callback?provider=google", provider.RedirectUri), provider.Scopes)
			providers = append(providers, prov)
		default:
			return nil, fmt.Errorf("unknown provider %s, known providers are google, unsafe", provider.ProviderName)
		}
	}

	goth.UseProviders(providers...)

	a.DB = db

	return &a, nil
}

// GetExistingUserFromSession takes a request and returns an existing user if it already exists, if one does not exist it returns an error
func (a *UserSessionManager) GetExistingUserByID(id string) (*users.User, error) {

	if id == "" {
		return nil, errors.New("invalid empty id")
	}

	res := a.DB.QueryRow(`SELECT id,email,username FROM accounts WHERE id = ?`, id)

	var userInfo users.User
	err := res.Scan(&userInfo.ID, &userInfo.Email, &userInfo.Username)

	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// GetExistingUserFromSession takes a request and returns an existing user if it already exists, if one does not exist it returns an error
func (a *UserSessionManager) GetExistingUserFromSession(request *http.Request) (*users.User, error) {
	internalID, err := gothic.GetFromSession(InternalId, request)
	if err != nil {
		return nil, err
	}

	if internalID == "" {
		return nil, errors.New("invalid empty id")
	}

	res := a.DB.QueryRow(`SELECT id,email,username FROM accounts WHERE id = ?`, internalID)

	var userInfo users.User
	err = res.Scan(&userInfo.ID, &userInfo.Email, &userInfo.Username)

	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (a *UserSessionManager) CreateNewOrGetExistingAccountAccountWithProviderData(ctx context.Context, user ProviderUserData) (*users.User, error) {
	// Once we have gotten the user's login provider data, we can query the database for the user based on their provider info
	tx, err := a.DB.BeginTx(ctx, &sql.TxOptions{})

	res := tx.QueryRow(`
			SELECT 
			    id, email, username 
			FROM accounts 
			    JOIN accounts_providers 
			ON accounts.id = accounts_providers.account_id 
			WHERE provider_account_id = ? AND provider_id = ?
		`, user.UserID, user.Provider)

	var userInfo users.User

	err = res.Scan(&userInfo.ID, &userInfo.Email, &userInfo.Username)

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Error("failed to retrieve value from db while querying by provider ", err)
		return nil, err
	} else if errors.Is(err, sql.ErrNoRows) {
		userInfo.Username = user.Name
		userInfo.Email = user.Email

		token := readable.NewUserID()
		userInfo.ID = token.String()

		log.Infof("No account for user, creating one. User ID: %s, provider %s", userInfo.ID, user.Provider)

		_, err = tx.Exec(`INSERT INTO accounts (id, username, email) VALUES (?,?,?)`, userInfo.ID, userInfo.Username, userInfo.Email)

		if err != nil {
			log.Error("failed to create account ", err)
			tx.Rollback()
			return nil, err
		}

		_, err = tx.Exec(`INSERT INTO accounts_providers (provider_id, account_id, provider_account_id) VALUES (?,?,?)`, user.Provider, userInfo.ID, user.UserID)

		if err != nil {
			log.Error("error inserting provider link", err)
			tx.Rollback()
			return nil, err
		}

		tx.Commit()
		log.Info("User Created")

	}

	return &userInfo, nil
}

type LinkState struct {
	Link      bool   `json:"Link,omitempty"`
	AccountId string `json:"AccountId"`
	Rand      []byte `json:"Rand,omitempty"`
}

func (l *LinkState) randomize() {
	nonceBytes := make([]byte, 50)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("gothic: source of randomness unavailable: " + err.Error())
	}
	l.Rand = nonceBytes
}

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

func (l *LinkState) Decode(source string) error {
	return json.NewDecoder(base64.NewDecoder(base64.StdEncoding, strings.NewReader(source))).Decode(l)
}

func (a *UserSessionManager) BeginAuthFlow(request *http.Request, writer http.ResponseWriter) {
	gothic.BeginAuthHandler(writer, request)
}

func (a *UserSessionManager) PersistUserToSession(user users.User, request *http.Request, writer http.ResponseWriter) error {
	return gothic.StoreInSession(InternalId, user.ID, request, writer)
}

// LinkProviderToAccount takes an account id and provider user data and links the provider user data to the account.
func (a *UserSessionManager) LinkProviderToAccount(ctx context.Context, accountID string, provider ProviderUserData) error {
	tx, err := a.DB.BeginTx(ctx, &sql.TxOptions{})

	if err != nil {
		return err
	}

	_, err = tx.Exec(`INSERT INTO accounts_providers (provider_id, account_id, provider_account_id) VALUES (?,?,?)`, provider.Provider, accountID, provider.UserID)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()

	return nil
}

func (a *UserSessionManager) AuthenticateAndGetAuthorizedUserData(request *http.Request, writer http.ResponseWriter, filters []Filter) (*ProviderUserData, error) {
	provider := request.URL.Query().Get("provider")

	var user ProviderUserData

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
