package oidc

import (
	"net/http"
	"time"

	"context"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

// ResponseMode ..
type ResponseMode = string

const (
	// ResponseModeFormPost ...
	ResponseModeFormPost ResponseMode = "form_post"
	// ResponseModeQuery ..
	ResponseModeQuery ResponseMode = "query"
)

// Options is the configuration required for running the oidc server
type Options struct {
	Issuer string

	CookieOptions CookieOptions

	Prefix string

	SignInPath  string
	SignOutPath string

	SignInCallbackPath  string
	SignOutCallbackPath string

	PostSignInRedirect  string
	PostSignOutRedirect string

	ResponseType string
	ResponseMode ResponseMode

	PostSignInRedirectHandler  http.Handler
	PostSignOutRedirectHandler http.Handler

	Provider oidc.Provider
	Config   oauth2.Config

	NotFoundHandler http.Handler

	Client http.Client

	ErrorLogger *log.Logger

	TempCodec         securecookie.Codec
	RedirectionMaxAge int

	IDTokenVerifier *oidc.IDTokenVerifier
	LogoutURI       string

	AuthHandler AuthHandler
}

// CookieOptions is the various cookie options that are configurable for the identity cookie
type CookieOptions struct {
	Name    string // Default: oidc
	Expires time.Time
	MaxAge  int
	Domain  string
	Path    string
}

// Option is the type used to modify the default Options
type Option func(*Options)

// DefaultOptions ...
func DefaultOptions() Options {
	return Options{
		Prefix: "/oidc",

		SignInPath:  "/oidc/sign-in",
		SignOutPath: "/oidc/sign-out",

		PostSignOutRedirect: "/",
		PostSignInRedirect:  "/",

		SignInCallbackPath:  "/oidc/sign-in-oidc",
		SignOutCallbackPath: "/oidc/sign-out-oidc",

		TempCodec: securecookie.New(
			[]byte("development-credentials-hash----"),
			nil,
		),

		RedirectionMaxAge: 25 * 60,

		ResponseMode: ResponseModeFormPost,
		ResponseType: "code id_token",

		CookieOptions: CookieOptions{
			Name: "oidc",
			Path: "/",
		},

		Config: oauth2.Config{
			Scopes: []string{oidc.ScopeOpenID, "profile"},
		},

		NotFoundHandler: http.NotFoundHandler(),

		Client: http.Client{
			Timeout: 10 * time.Second,
		},

		ErrorLogger: log.New(os.Stderr, "oidc: ", 0),
	}
}

// OpenIDConnect ...
func OpenIDConnect(iss, clientID, clientSecret string, opts ...Option) (func(http.Handler) http.Handler, error) {
	o := DefaultOptions()
	o.Issuer = iss
	o.Config.ClientID = clientID
	o.Config.ClientSecret = clientSecret

	for _, f := range opts {
		f(&o)
	}

	if err := prepareOptions(&o); err != nil {
		return nil, err
	}

	h := handlerFromOptions(&o)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.RequestURI) >= len(o.Prefix) && r.RequestURI[:len(o.Prefix)] == o.Prefix {
				h.ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func Must(h func(http.Handler) http.Handler, err error) func(http.Handler) http.Handler {
	if err != nil {
		panic(err)
	}

	return h
}

func prepareOptions(o *Options) error {
	provider, err := oidc.NewProvider(context.Background(), o.Issuer)
	if err != nil {
		return err
	}

	o.Config.Endpoint = provider.Endpoint()

	o.IDTokenVerifier = provider.Verifier(&oidc.Config{ClientID: o.Config.ClientID})

	if o.AuthHandler == nil {
		o.AuthHandler = o
	}

	if o.PostSignInRedirectHandler == nil {
		o.PostSignInRedirectHandler = http.RedirectHandler(o.PostSignInRedirect, http.StatusFound)
	}

	if o.PostSignOutRedirectHandler == nil {
		o.PostSignOutRedirectHandler = http.RedirectHandler(o.PostSignOutRedirect, http.StatusFound)
	}

	if o.RedirectionMaxAge < 0 {
		o.RedirectionMaxAge = 0
	}

	if s, ok := o.TempCodec.(*securecookie.SecureCookie); ok {
		s.MaxAge(o.RedirectionMaxAge)
	}

	discoveryURI := strings.TrimSuffix(o.Issuer, "/") + "/.well-known/openid-configuration"

	res, err := o.Client.Get(discoveryURI)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var discoResp struct {
		EndSessionURI string `json:"end_session_endpoint"`
	}

	if err := json.NewDecoder(res.Body).Decode(&discoResp); err != nil {
		return err
	}

	o.LogoutURI = discoResp.EndSessionURI

	return nil
}
