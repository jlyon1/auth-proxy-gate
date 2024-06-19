package transport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/readable"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/transport/ui"
	"github.com/a-h/templ"
	chi "github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"go.uber.org/zap"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Http struct {
	ListenURL string `json:"ListenURL,omitempty"`
	Secure    bool   `json:"Secure"`

	ClientID     string   `json:"ClientID"`
	ClientSecret string   `json:"ClientSecret"`
	RedirectURI  string   `json:"RedirectURI"`
	Proxy        string   `json:"Proxy"`
	SecretKey    string   `json:"SecretKey"`
	AllowList    []string `json:"AllowList"`

	DB             *sql.DB // TODO: This struct needs a NewFunc
	googleProvider *google.Provider
}

type UserInfo struct {
	ID       string
	Email    string
	Username string
}

func (h *Http) ProactiveTokenRefresh(log *zap.SugaredLogger) error {
	//return h.DB.Update(func(tx *bolt.Tx) error {
	//	b, err := tx.CreateBucketIfNotExists([]byte("tokens"))
	//	if err != nil {
	//		return err
	//	}
	//
	//	return b.ForEach(func(k, v []byte) error {
	//		var userData goth.User
	//
	//		err := json.Unmarshal(v, &userData)
	//		if err != nil {
	//			log.Error("error unmarshalling data for token ", string(k), string(v))
	//			return nil
	//		}
	//
	//		if !userData.ExpiresAt.After(time.Now().Add(15 * time.Minute)) {
	//			log.Info("refreshing token for user ", string(k))
	//
	//			authToken, err := h.googleProvider.RefreshToken(userData.RefreshToken)
	//			if err != nil {
	//				return err
	//			}
	//
	//			userData.AccessToken = authToken.AccessToken
	//			userData.RefreshToken = authToken.RefreshToken
	//			userData.ExpiresAt = authToken.Expiry
	//
	//			d, _ := json.Marshal(userData)
	//
	//			b.Put(k, d)
	//
	//			log.Info("refreshed user data for user ", string(k), " new expiry is ", userData.ExpiresAt)
	//		}
	//		return nil
	//	})
	//})
	return nil
}

func (h *Http) ListenAndServe(log *zap.SugaredLogger, ctx context.Context) error {
	r := chi.NewRouter()
	key := ""
	maxAge := 86400 * 30 // 30 days

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = h.Secure

	gothic.Store = store

	h.googleProvider = google.New(h.ClientID, h.ClientSecret, fmt.Sprintf("%s/auth/callback?provider=google", h.RedirectURI), "email")

	goth.UseProviders(
		//TODO We should validate or document these
		h.googleProvider,
	)

	url, _ := url.Parse(h.Proxy)
	p := httputil.NewSingleHostReverseProxy(url)

	r.HandleFunc("/*", func(writer http.ResponseWriter, request *http.Request) {
		ctx := context.Background()

		internalID, err := gothic.GetFromSession("internal_id", request)

		var components []templ.Component

		if internalID != "" || err == nil {
			res := h.DB.QueryRow(`SELECT id,email,username FROM accounts WHERE id = ?`, internalID)

			var userInfo UserInfo

			err := res.Scan(&userInfo.ID, &userInfo.Email, &userInfo.Username)

			if err != nil {
				log.Error("error querying userdata from db")
			}

			log.Debug("user is authorized, proxying ", internalID)
			request.Host = url.Host
			request.Header.Add("X-Proxy-Authorization", internalID)

			// If no proxy is set, dump the token
			if h.Proxy == "" {
				data := struct {
					UserID string `json:"UserID"`
					Ident  string `json:"Ident"`
					Email  string `json:"Email"`
				}{
					UserID: internalID,
					Ident:  fmt.Sprintf("%s/auth/ident", h.RedirectURI),
					Email:  userInfo.Email,
				}

				writer.Header().Set("content-type", "application/json")
				encodedData, _ := json.Marshal(data)

				writer.Write(encodedData)
				return
			}

			p.ServeHTTP(writer, request)
		} else if err != nil || internalID == "" {
			log.Debugf("user is not authorized, requesting login %s %s", internalID, err)
			components = append(components, ui.LoginButton("", ""))
		}

		err = ui.Page("Login", components).Render(ctx, writer)

		if err != nil {
			return
		}
	})

	r.Get("/auth/callback", func(writer http.ResponseWriter, request *http.Request) {
		provider := request.URL.Query().Get("provider")

		log.Infof("Login Callback with provider %s", provider)

		if provider == "" {
			log.Error("provier cannot be empty")
			writeInternalError(writer, "invalid provider")
			return
		}

		user, err := gothic.CompleteUserAuth(writer, request)
		if err != nil {
			log.Error("error completing user auth", zap.Error(err))
			writeInternalError(writer, "error completing user auth")
			return
		}

		found := false
		for _, entry := range h.AllowList {
			if entry == user.Email {
				found = true
				break
			}
		}

		if len(h.AllowList) == 0 {
			found = true
		}

		if !found {
			log.Infof("found not allowed user %s", user.Email)
			writer.WriteHeader(401)
			writer.Write([]byte("unauthorized"))
			return
		}

		tx, err := h.DB.BeginTx(ctx, &sql.TxOptions{})

		res := tx.QueryRow(`
			SELECT 
			    id, email, username 
			FROM accounts 
			    JOIN accounts_providers 
			ON accounts.id = accounts_providers.account_id 
			WHERE provider_account_id = ? AND provider_id = ?
		`, user.UserID, provider)

		var userInfo UserInfo

		err = res.Scan(&userInfo.ID, &userInfo.Email, &userInfo.Username)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			log.Error("failed to retrieve value from db ", err)
			writeInternalError(writer, "failed to retrieve value from db")
			return
		} else if errors.Is(err, sql.ErrNoRows) {

			userInfo.Username = user.Name
			userInfo.Email = user.Email

			token := readable.NewUserID()
			userInfo.ID = token.String()

			log.Infof("No account for user, creating one. User ID: %s, provider %s", userInfo.ID, provider)

			_, err = tx.Exec(`INSERT INTO accounts (id, username, email) VALUES (?,?,?)`, userInfo.ID, userInfo.Username, userInfo.Email)

			if err != nil {
				log.Error("failed to create account ", err)
				tx.Rollback()
				writeInternalError(writer, "error creating account")
				return
			}

			_, err = tx.Exec(`INSERT INTO accounts_providers (provider_id, account_id, provider_account_id) VALUES (?,?,?)`, provider, userInfo.ID, user.UserID)

			if err != nil {
				log.Error("error inserting provider link", err)
				tx.Rollback()
				writeInternalError(writer, "error creating account")
			}

			tx.Commit()
			log.Info("User Created")

		}

		err = gothic.StoreInSession("internal_id", userInfo.ID, request, writer)
		if err != nil {
			log.Error("error storing in session", err)
			writeInternalError(writer, "error authorizing account")
			return
		}

		log.Infof("User authorized and info stored in session %s", userInfo.ID)

		http.Redirect(writer, request, "/", 302)

		if err != nil {
			return
		}
	})

	r.Get("/auth", func(res http.ResponseWriter, req *http.Request) {
		gothic.BeginAuthHandler(res, req)
	})

	r.Get("/auth/ident", func(res http.ResponseWriter, req *http.Request) {

		var data goth.User

		uid := req.Header.Get("Authorization")

		log.Info("got user id from request ", uid)

		_, err := readable.NewTokenFromString(uid)
		if err != nil {
			log.Error("token in bad format ", err)
			res.WriteHeader(http.StatusUnauthorized)
			return
		}

		//err = h.DB.View(getUserFromDbFunc(uid, data))

		if err != nil {
			log.Error(err)
			writeInternalError(res, "failed to read user data")
			return
		}

		d, _ := json.Marshal(data)

		res.Header().Set("content-type", "application/json")

		res.Write(d)
	})

	log.Infof("Listening on %s", h.ListenURL)

	server := http.Server{
		Addr:    h.ListenURL,
		Handler: r,
	}

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		<-ctx.Done()
		if err := server.Close(); err != nil {
			log.Fatalf("HTTP close error: %v", err)
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				wg.Done()
				return
			case <-time.After(time.Minute):
				log.Info("checking for any token refreshes")
				err := h.ProactiveTokenRefresh(log)
				if err != nil {
					log.Warn("error refreshing tokens ", err)
				}
			}
		}
	}()

	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server error: %v", err)
		return err
	}

	wg.Wait()

	return nil
}

func storeAuthDataInBoltFunc(writer http.ResponseWriter, request *http.Request, user goth.User, log *zap.SugaredLogger) func(tx *bolt.Tx) error {
	return func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("sessions"))
		if err != nil {
			return err
		}

		var tok readable.Token

		userIDKey := []byte(user.UserID)
		tokenInDB := b.Get(userIDKey)

		if tokenInDB == nil {
			// Generate a new token and store it
			token := readable.NewToken()

			log.Debug("Generated internal token for user", token.String(), user.Email)

			err := b.Put(userIDKey, []byte(token.String()))
			if err != nil {
				return err
			}

			tok = token
		} else {
			t, err := readable.NewTokenFromString(string(tokenInDB))
			if err != nil {
				return err
			}

			tok = *t
		}

		err = gothic.StoreInSession("internal_token", tok.String(), request, writer)
		if err != nil {
			log.Error("error storing session field token", err)
		}

		// At this point we should store the rest of the user data in bolt

		b, err = tx.CreateBucketIfNotExists([]byte("tokens"))
		if err != nil {
			return err
		}

		d, err := json.Marshal(user)
		if err != nil {
			return err
		}

		err = b.Put([]byte(tok.String()), d)
		if err != nil {
			return err
		}

		return nil
	}
}

func getUserFromDbFunc(uid string, data goth.User) func(tx *bolt.Tx) error {
	return func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		if b == nil {
			return errors.New("unexpected missing bucket")
		}

		rawData := b.Get([]byte(uid))

		if rawData == nil {
			return errors.New("unexpected empty user data")
		}

		return json.Unmarshal(rawData, &data)

	}
}
