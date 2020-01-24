package oidc

import "net/http"

// WithPostSignInHandler can be used to customise Post SignIn Redirection
func WithPostSignInHandler(h http.Handler) Option {
	return func(o *Options) {
		o.PostSignInRedirectHandler = h
	}
}

// WithPostSignInHandler can be used to customise Post SignIn Redirection
func WithPostSignInHandlerFunc(h func(w http.ResponseWriter, r *http.Request)) Option {
	return func(o *Options) {
		o.PostSignInRedirectHandler = http.HandlerFunc(h)
	}
}

func WithCookieOptions(c CookieOptions) Option {
	return func(o *Options) {
		o.CookieOptions = c
	}
}
