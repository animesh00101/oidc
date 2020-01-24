package oidc

import (
	"bytes"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	stateKey = "state"
	nonceKey = "nonce"
)

func handlerFromOptions(opt *Options) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(opt.SignInPath, opt.AuthHandler.SignIn)
	mux.HandleFunc(opt.SignInCallbackPath, opt.AuthHandler.SignInCallback)

	mux.HandleFunc(opt.SignOutPath, opt.AuthHandler.SignOut)
	mux.HandleFunc(opt.SignOutCallbackPath, opt.AuthHandler.SignOutCallback)

	mux.Handle("/", opt.NotFoundHandler)

	return mux
}

func (o *Options) SignIn(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()

	if err := o.encryptTempToCookie(w, r, stateKey, state, o.SignInCallbackPath); err != nil {
		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	nonce := uuid.New().String()

	if err := o.encryptTempToCookie(w, r, nonceKey, nonce, o.SignInCallbackPath); err != nil {
		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	authOptions := make([]oauth2.AuthCodeOption, 0, 4+len(r.URL.Query()))

	authOptions = append(authOptions,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("response_type", o.ResponseType),
		oauth2.SetAuthURLParam("response_mode", o.ResponseMode),
		oauth2.SetAuthURLParam("redirect_uri", fmt.Sprintf("%s://%s%s", scheme, r.Host, o.SignInCallbackPath)),
	)

	for key := range r.URL.Query() {
		val := r.URL.Query().Get(key)
		authOptions = append(authOptions, oauth2.SetAuthURLParam(key, val))
	}

	authCodeUrl := o.Config.AuthCodeURL(
		state,
		authOptions...,
	)

	http.Redirect(w, r, authCodeUrl, http.StatusFound)
}

func (o *Options) SignInCallback(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	recState := r.FormValue(stateKey)

	state, err := o.decryptTempFromCookie(w, r, stateKey)
	if err != nil {
		if err == http.ErrNoCookie {
			o.ErrorLogger.Println("state cookie not found")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if state != recState {
		o.ErrorLogger.Println("state mismatch, received state:", recState, "expected state:", state)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	oauth2Token, err := o.Config.Exchange(
		r.Context(),
		r.FormValue("code"),
		oauth2.SetAuthURLParam("redirect_uri", fmt.Sprintf("%s://%s%s", scheme, r.Host, o.SignInCallbackPath)),
	)
	if err != nil {
		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := o.IDTokenVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce, err := o.decryptTempFromCookie(w, r, nonceKey)
	if err != nil {
		if err == http.ErrNoCookie {
			o.ErrorLogger.Println("nonce cookie not found")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if idToken.Nonce != nonce {
		http.Error(w, "Invalid ID Token nonce", http.StatusInternalServerError)
		return
	}

	if err := o.SetAuthCookie(w, r, &Token{
		IDToken:      rawIDToken,
		AccessToken:  oauth2Token.AccessToken,
		Expiry:       oauth2Token.Expiry,
		RefreshToken: oauth2Token.RefreshToken,
		TokenType:    oauth2Token.TokenType,
	}); err != nil {
		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	o.PostSignInRedirectHandler.ServeHTTP(w, r)
}

func (o *Options) SignOutCallback(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	recState := r.FormValue(stateKey)

	state, err := o.decryptTempFromCookie(w, r, stateKey)
	if err != nil {
		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if recState != state {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	o.RemoveAuthCookie(w)
	o.PostSignOutRedirectHandler.ServeHTTP(w, r)
}

func (o *Options) SignOut(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()
	if err := o.encryptTempToCookie(w, r, stateKey, state, o.SignOutCallbackPath); err != nil {
		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	v := url.Values{
		"post_logout_redirect_uri": {fmt.Sprintf("%s://%s%s", scheme, r.Host, o.SignOutCallbackPath)},
		"state":                    {state},
	}

	if token, err := o.AuthCookie(w, r); err == nil {
		if token.IDToken != "" {
			v.Set("id_token_hint", token.IDToken)
		}
	}

	var buf bytes.Buffer
	buf.WriteString(o.LogoutURI)
	if strings.Contains(o.LogoutURI, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}

	buf.WriteString(v.Encode())
	o.RemoveAuthCookie(w)
	http.Redirect(w, r, buf.String(), http.StatusFound)
}

func (o *Options) SetAuthCookie(w http.ResponseWriter, r *http.Request, token *Token) error {
	http.SetCookie(w, &http.Cookie{
		Name:     o.CookieOptions.Name,
		Value:    token.AccessToken,
		MaxAge:   o.CookieOptions.MaxAge,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		Expires:  o.CookieOptions.Expires,
		Domain:   o.CookieOptions.Domain,
		Path:     o.CookieOptions.Path,
		SameSite: o.CookieOptions.SameSite,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sign_out",
		Value:    token.IDToken,
		Expires:  token.Expiry,
		Path:     o.SignOutPath,
		Domain:   o.CookieOptions.Domain,
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})

	// TODO: Something About Refresh Token

	return nil
}

func (o *Options) AuthCookie(w http.ResponseWriter, r *http.Request) (*Token, error) {
	c, err := r.Cookie(o.CookieOptions.Name)
	if err != nil {
		return nil, err
	}

	idc, err := r.Cookie("sign_out")
	if err != nil {
		idc = &http.Cookie{
			Value: "",
		}
	}

	return &Token{
		AccessToken: c.Value,
		IDToken:     idc.Value,
	}, nil
}

func (o *Options) RemoveAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   o.CookieOptions.Name,
		MaxAge: -1,
		Domain: o.CookieOptions.Domain,
		Path:   o.CookieOptions.Path,
	})
}

func (o *Options) encryptTempToCookie(w http.ResponseWriter, r *http.Request, name, value, path string) error {
	encVal, err := o.TempCodec.Encode(name, value)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    encVal,
		Path:     path,
		Domain:   o.CookieOptions.Domain,
		MaxAge:   o.RedirectionMaxAge, // In Seconds
		Secure:   r.TLS != nil,
		HttpOnly: true,
		Expires:  time.Now().UTC().Add(time.Duration(o.RedirectionMaxAge) * time.Second),
	})

	return nil
}

func (o *Options) decryptTempFromCookie(w http.ResponseWriter, r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	var value string
	if err := o.TempCodec.Decode(name, c.Value, &value); err != nil {
		return "", err
	}

	c.MaxAge = -1
	http.SetCookie(w, c)

	return value, nil
}

type AuthHandler interface {
	SignIn(http.ResponseWriter, *http.Request)
	SignInCallback(http.ResponseWriter, *http.Request)

	SignOut(http.ResponseWriter, *http.Request)
	SignOutCallback(http.ResponseWriter, *http.Request)
}

type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// IDToken is the OpenID addition to the excellent OAuth 2.0
	IDToken string `json:"id_token,omitempty"`
}
