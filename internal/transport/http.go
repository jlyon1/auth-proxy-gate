package transport

import (
	"context"
	"fmt"
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
)

type Http struct {
	ListenURL string `json:"ListenURL,omitempty"`
	Secure    bool   `json:"Secure"`

	ClientID     string `json:"ClientID"`
	ClientSecret string `json:"ClientSecret"`
	RedirectURI  string `json:"RedirectURI"`
	Proxy        string `json:"Proxy"`
	SecretKey    string `json:"SecretKey"`
}

func (h *Http) ListenAndServe(log *zap.SugaredLogger) error {
	r := chi.NewRouter()
	key := h.SecretKey
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

		email, err := gothic.GetFromSession("email", request)

		components := []templ.Component{}

		if email != "" {
			request.Host = url.Host
			p.ServeHTTP(writer, request)
		} else if err != nil || email == "" {
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
			fmt.Fprintln(writer, err)
			return
		}

		gothic.StoreInSession("email", user.Email, request, writer)

		http.Redirect(writer, request, "/", 302)

		if err != nil {
			return
		}
	})

	r.Get("/auth", func(res http.ResponseWriter, req *http.Request) {
		gothic.BeginAuthHandler(res, req)
	})

	log.Infof("Listening on %s", h.ListenURL)

	return http.ListenAndServe(h.ListenURL, r)
}
