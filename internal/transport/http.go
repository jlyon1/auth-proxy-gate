package transport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/auth"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/transport/ui"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/users"
	"github.com/a-h/templ"
	chi "github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

type Http struct {
	ListenURL string `json:"ListenURL,omitempty"`

	ClientID     string   `json:"ClientID"`
	ClientSecret string   `json:"ClientSecret"`
	RedirectURI  string   `json:"RedirectURI"`
	Proxy        string   `json:"Proxy"`
	AllowList    []string `json:"AllowList"`

	DB            *sql.DB // TODO: This struct needs a NewFunc
	Authenticator *auth.UserSessionManager
}

func (h *Http) ProactiveTokenRefresh(log *zap.SugaredLogger) error {

	return nil
}

func (h *Http) ListenAndServe(log *zap.SugaredLogger, ctx context.Context) error {
	r := chi.NewRouter()

	url, _ := url.Parse(h.Proxy)
	p := httputil.NewSingleHostReverseProxy(url)

	r.HandleFunc("/*", func(writer http.ResponseWriter, request *http.Request) {
		ctx := context.Background()

		userInfo, err := h.Authenticator.GetExistingUserFromSession(request)
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
		_, err := h.Authenticator.GetExistingUserFromSession(request)
		if err != nil {
			log.Error(err)
			http.Redirect(writer, request, "/", 302)
			return
		}

		ui.Page("Link Account", []templ.Component{ui.Link("", "")}).Render(ctx, writer)
	})

	r.Get("/auth/callback", func(writer http.ResponseWriter, request *http.Request) {
		log.Infof("Login Callback called")

		user, err := h.Authenticator.AuthenticateAndGetAuthorizedUserData(request, writer, []auth.Filter{&auth.EmailAllowListFilter{AllowedEmails: h.AllowList}})

		if err != nil {
			log.Info("user is not authenticated properly ", err)
			writer.WriteHeader(401)
			writer.Write([]byte("unauthorized"))
			return
		}

		state := request.URL.Query().Get("state")

		ls := auth.LinkState{}
		err = ls.Decode(state)

		if err != nil {
			log.Info("no link state on request", err)
		}

		link := request.URL.Query().Get("link")
		if link == "true" || ls.Link {
			log.Info("Account Linking Flow")

			var currentUser *users.User

			if ls.AccountId != "" {
				log.Info("using account id from state")
				currentUser, err = h.Authenticator.GetExistingUserByID(ls.AccountId)
				if err != nil {
					log.Error(err)
					http.Redirect(writer, request, "/", 302)
					return
				}
			} else {
				log.Info("using account id from session")
				currentUser, err = h.Authenticator.GetExistingUserFromSession(request)
				if err != nil {
					log.Error(err)
					http.Redirect(writer, request, "/", 302)
					return
				}

			}

			err = h.Authenticator.LinkProviderToAccount(ctx, currentUser.ID, *user)
			if err != nil {
				log.Error(err)
				writeInternalError(writer, "error")
				return
			}

			err = h.Authenticator.PersistUserToSession(*currentUser, request, writer)
			if err != nil {
				log.Error("error storing in auth", err)
				writeInternalError(writer, "error authorizing account")
				return
			}

			log.Infof("account linked")
			http.Redirect(writer, request, "/", 302)

			return
		}

		userInfo, err := h.Authenticator.CreateNewOrGetExistingAccountAccountWithProviderData(ctx, *user)
		if err != nil {
			log.Error("error creating an account", err)
			writeInternalError(writer, "error authorizing account")
			return
		}

		err = h.Authenticator.PersistUserToSession(*userInfo, request, writer)
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
		user, err := h.Authenticator.GetExistingUserFromSession(req)
		ls := auth.LinkState{}
		if err == nil {
			fmt.Printf("user %s is linking", user.ID)
			ls.Link = true
			ls.AccountId = user.ID
		}

		encoded, _ := ls.Encode()

		// Overwrite the state with the link state, so we can decode it later
		req.URL.RawQuery = req.URL.RawQuery + "&state=" + encoded

		h.Authenticator.BeginAuthFlow(req, res)

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
