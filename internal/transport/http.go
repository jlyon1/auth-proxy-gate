package transport

import (
	"context"
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

func (h *Http) ListenAndServe(log *zap.SugaredLogger, ctx context.Context) error {
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
		if err != nil {
			log.Error("error getting email from session", err)
		}

		components := []templ.Component{}

		if email != "" {
			log.Debug("user is authorized, proxying", zap.String("email", email))
			request.Host = url.Host
			p.ServeHTTP(writer, request)
		} else if err != nil || email == "" {
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

		token := readable.NewToken()

		log.Debug("Generated internal token for user", token.String(), user.Email)

		err = gothic.StoreInSession("internal_token", token.String(), request, writer)
		if err != nil {
			log.Error("error storing session field token", err)
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
		// Here we will allow the application we are proxying for make requests back to this service to get information about the user.
		//auth := req.Header.Get("Authorization")
		//if auth == "" {
		//	res.Write([]byte("unauthorized"))
		//	res.WriteHeader(http.StatusUnauthorized)
		//}

		//ctx := context.Background()

		val, err := gothic.GetFromSession("access_token", req)
		if err != nil {
			return
		}

		res.Write([]byte(val))
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
