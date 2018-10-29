package oidc

import "net/http"

// WithPostSignInHandler can be used to customise Post SignIn Redirection
func WithPostSignInHandler(h http.Handler) Option {
	return func(o *Options) {
		o.PostSignInRedirectHandler = h
	}
}