package transport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/auth"
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
	Authenticator  *auth.Authenticator
	googleProvider *google.Provider
}

func (h *Http) ProactiveTokenRefresh(log *zap.SugaredLogger) error {

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

		userInfo, err := h.Authenticator.GetUserFromSession(request)
		var components []templ.Component

		if err != nil {
			log.Debugf("user is not authorized, requesting login %s %s", err)
			components = append(components, ui.LoginButton("", ""))
			_ = ui.Page("Login", components).Render(ctx, writer)

			return
		}

		log.Debug("user is authorized, proxying ", userInfo.ID)
		request.Host = url.Host
		request.Header.Add("X-Proxy-Authorization", userInfo.ID)

		// If no proxy is set, dump the token
		if h.Proxy == "" {
			data := struct {
				UserID string `json:"UserID"`
				Ident  string `json:"Ident"`
				Email  string `json:"Email"`
			}{
				UserID: userInfo.ID,
				Ident:  fmt.Sprintf("%s/auth/ident", h.RedirectURI),
				Email:  userInfo.Email,
			}

			writer.Header().Set("content-type", "application/json")
			encodedData, _ := json.Marshal(data)

			writer.Write(encodedData)
			return
		}

		p.ServeHTTP(writer, request)

	})

	r.Get("/auth/link", func(writer http.ResponseWriter, request *http.Request) {
		_, err := h.Authenticator.GetUserFromSession(request)
		if err != nil {
			log.Error(err)
			http.Redirect(writer, request, "/", 302)
			return
		}

		ui.Page("Link Account", []templ.Component{ui.Link("", "")}).Render(ctx, writer)
	})

	r.Get("/auth/callback", func(writer http.ResponseWriter, request *http.Request) {
		log.Infof("Login Callback called")

		user, err := auth.AuthenticateAndGetAuthorizedUserData(request, writer, []auth.Filter{&auth.EmailAllowListFilter{AllowedEmails: h.AllowList}})

		if err != nil {
			log.Info("user is not authenticated properly ", err)
			writer.WriteHeader(401)
			writer.Write([]byte("unauthorized"))
			return
		}

		link := request.URL.Query().Get("link")
		if link == "true" {
			log.Info("Account Linking Flow")

			currentUserId, err := gothic.GetFromSession(auth.InternalId, request)
			if err != nil {
				log.Error(err)
				http.Redirect(writer, request, "/", 302)
				return
			}

			err = h.Authenticator.LinkProviderToAccount(ctx, currentUserId, *user)
			if err != nil {
				log.Error(err)
				writeInternalError(writer, "error")
				return
			}

			log.Infof("account linked")
			http.Redirect(writer, request, "/", 302)

			return
		}

		userInfo, err := h.Authenticator.CreateNewAccountWithProviderDataOrGetExistingAccount(ctx, *user)

		err = gothic.StoreInSession(auth.InternalId, userInfo.ID, request, writer)
		if err != nil {
			log.Error("error storing in auth", err)
			writeInternalError(writer, "error authorizing account")
			return
		}

		log.Infof("User authorized and info stored in auth %s", userInfo.ID)

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
