package transport

import (
	"context"
	"encoding/json"
	"errors"
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

	bolt "go.etcd.io/bbolt"
)

type Http struct {
	ListenURL string `json:"ListenURL,omitempty"`
	Secure    bool   `json:"Secure"`

	ClientID     string `json:"ClientID"`
	ClientSecret string `json:"ClientSecret"`
	RedirectURI  string `json:"RedirectURI"`
	Proxy        string `json:"Proxy"`
	SecretKey    string `json:"SecretKey"`

	DB bolt.DB // TODO: This struct needs a NewFunc
}

type UserData struct {
	Email       string `json:"Email,omitempty"`
	AccessToken string `json:"AccessToken,omitempty"`
	UserID      string `json:"UserID"`
}

type InternalError struct {
	Message string `json:"message"`
}

func (i InternalError) WriteTo(w http.ResponseWriter) {
	data, _ := json.Marshal(i)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write(data)
}

func internalError(w http.ResponseWriter, reason string) {
	InternalError{
		reason,
	}.WriteTo(w)
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

	goth.UseProviders(
		google.New(h.ClientID, h.ClientSecret, h.RedirectURI, "email"),
	)

	url, _ := url.Parse(h.Proxy)
	p := httputil.NewSingleHostReverseProxy(url)

	r.HandleFunc("/*", func(writer http.ResponseWriter, request *http.Request) {
		ctx := context.Background()

		internalToken, err := gothic.GetFromSession("internal_token", request)
		if err != nil {
			log.Error("error getting internal_token from session", err)
			internalError(writer, "")
			return
		}

		err = h.DB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("sessions"))
			if b == nil {
				return errors.New("unexpected missing bucket")
			}

			rawData := b.Get([]byte(internalToken))
			if rawData == nil {
				return errors.New("no session for user")
			}

			return nil
		})

		var components []templ.Component

		if internalToken != "" && err == nil {
			log.Debug("user is authorized, proxying ", internalToken)
			request.Host = url.Host
			request.Header.Add("X-Proxy-Authorization", internalToken)
			p.ServeHTTP(writer, request)
		} else if err != nil || internalToken == "" {
			log.Debug("user is not authorized, requesting login")
			components = append(components, ui.LoginButton("", ""))
		}

		err = ui.Page("Login", components).Render(ctx, writer)

		if err != nil {
			return
		}
	})

	r.Get("/auth/callback", func(writer http.ResponseWriter, request *http.Request) {

		user, err := gothic.CompleteUserAuth(writer, request)
		if err != nil {
			log.Error("error completing user auth", zap.Error(err))
			writer.WriteHeader(500)
			writer.Write([]byte("error completing user auth"))
			return
		}

		err = h.DB.Update(func(tx *bolt.Tx) error {
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

			d, err := json.Marshal(user)
			if err != nil {
				return err
			}

			err = b.Put([]byte(tok.String()), d)
			if err != nil {
				return err
			}

			return nil
		})

		if err != nil {
			log.Error("failed to retrieve value from db", err)
			internalError(writer, "failed to retrieve value from db")
			return
		}

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

		err = h.DB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("sessions"))
			if b == nil {
				return errors.New("unexpected missing bucket")
			}

			rawData := b.Get([]byte(uid))

			if rawData == nil {
				return errors.New("unexpected empty user data")
			}

			return json.Unmarshal(rawData, &data)

		})

		if err != nil {
			log.Error(err)
			internalError(res, "failed to read user data")
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

	go func() {
		<-ctx.Done()
		if err := server.Close(); err != nil {
			log.Fatalf("HTTP close error: %v", err)
		}
	}()

	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server error: %v", err)
		return err
	}

	return nil
}
