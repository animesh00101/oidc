package oidc

import (
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"context"
	"github.com/gorilla/securecookie"
	"log"
	"os"
	"strings"
	"encoding/json"
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

	Codecs []securecookie.Codec

	ErrorLogger *log.Logger

	TempCodec         securecookie.Codec
	RedirectionMaxAge int

	IDTokenVerifier *oidc.IDTokenVerifier
	LogoutURI       string

	AuthHandler AuthHandler
}

// CookieOptions is the various cookie options that are configurable for the identity cookie
type CookieOptions struct {
	Name    string // Default: raksh
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
		SignOutCallbackPath: "/oidc/sign-in-oidc",

		Codecs: securecookie.CodecsFromPairs(
			[]byte("development-credentials-hash"),
			[]byte("development-credentials-block"),
		),

		TempCodec: securecookie.CodecsFromPairs(
			[]byte("development-credentials-hash"),
			[]byte("development-credentials-block"),
		)[0],

		RedirectionMaxAge: 5 * 60,

		ResponseMode: ResponseModeFormPost,
		ResponseType: "id_token",

		CookieOptions: CookieOptions{
			Name:   "oidc",
			Path:   "/",
			MaxAge: 60,
		},

		Config: oauth2.Config{
			Scopes: []string{oidc.ScopeOpenID, "profile"},
		},

		NotFoundHandler: http.NotFoundHandler(),

		Client: http.Client{
			Timeout: 10 * time.Second,
		},

		ErrorLogger: log.New(os.Stderr, "oidc", log.LstdFlags),
	}
}

type authKey struct{}

var key authKey

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
			if r.RequestURI[:len(o.Prefix)] == o.Prefix {
				h.ServeHTTP(w, r)
				return
			}

			token, err := o.AuthCookie(w, r)
			if err != nil {
				o.ErrorLogger.Println(err)
				next.ServeHTTP(w, r)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), &key, token))

			next.ServeHTTP(w, r)
		})
	}, nil
}

func FromContext(ctx context.Context) *oauth2.Token {
	if t, ok := ctx.Value(&key).(*oauth2.Token); ok {
		return t
	}

	return nil
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

	for _, s := range o.Codecs {
		if cookie, ok := s.(*securecookie.SecureCookie); ok {
			cookie.MaxAge(o.CookieOptions.MaxAge)
		}
	}

	discoveryURI := strings.TrimSuffix(o.Issuer, "/") + ".well-known/openid-configuration"

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