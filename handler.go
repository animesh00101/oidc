package oidc

import (
	"net/http"
	"github.com/google/uuid"
	"time"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"fmt"
	"encoding/gob"
	"github.com/gorilla/securecookie"
	"net/url"
	"strings"
	"bytes"
)

const (
	stateKey = "state"
	nonceKey = "nonce"
)

func init() {
	gob.Register(&oauth2.Token{})
}

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

	authCodeUrl := o.Config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("response_type", o.ResponseType),
		oauth2.SetAuthURLParam("response_mode", o.ResponseMode),
		oauth2.SetAuthURLParam("redirect_uri", fmt.Sprintf("%s://%s%s", scheme, r.Host, o.SignInCallbackPath)),
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
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		o.ErrorLogger.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if state != recState {
		o.ErrorLogger.Println("state mismatch, received state:", recState, "expected state:", state)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	oauth2Token, err := o.Config.Exchange(r.Context(), r.FormValue("code"))
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
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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

	if err := o.SetAuthCookie(w, r, oauth2Token); err != nil {
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
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	o.PostSignInRedirectHandler.ServeHTTP(w, r)
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
		idToken, ok := token.Extra("id_token").(string)
		if ok {
			v.Set("id_token_hint", idToken)
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
	http.Redirect(w, r, buf.String(), http.StatusFound)
}

func (o *Options) SetAuthCookie(w http.ResponseWriter, r *http.Request, token *oauth2.Token) error {
	enc, err := securecookie.EncodeMulti(o.CookieOptions.Name, token, o.Codecs...)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     o.CookieOptions.Name,
		Value:    enc,
		MaxAge:   o.CookieOptions.MaxAge,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		Expires:  o.CookieOptions.Expires,
		Domain:   o.CookieOptions.Domain,
		Path:     o.CookieOptions.Path,
	})

	return nil
}

func (o *Options) AuthCookie(w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {
	c, err := r.Cookie(o.CookieOptions.Name)
	if err != nil {
		return nil, err
	}

	var token oauth2.Token
	if err := securecookie.DecodeMulti(o.CookieOptions.Name, c.Value, &token, o.Codecs...); err != nil {
		return nil, err
	}

	return &token, nil
}

func (o *Options) RemoveAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   o.CookieOptions.Name,
		MaxAge: -1,
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
