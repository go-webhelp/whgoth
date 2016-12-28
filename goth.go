// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package whgoth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"

	"github.com/jtolds/webhelp/whcompat"
	"github.com/jtolds/webhelp/wherr"
	"github.com/jtolds/webhelp/whmux"
	"github.com/jtolds/webhelp/whredir"
	"github.com/jtolds/webhelp/whroute"
	"github.com/jtolds/webhelp/whsess"
	"github.com/markbates/goth"
	"golang.org/x/net/context"
)

type AuthProvider struct {
	goth.Provider
	baseURL          string
	sessionNamespace string

	whmux.Dir
}

func newAuthProvider(p goth.Provider, baseURL, sessionNamespace string) (
	a *AuthProvider) {
	a = &AuthProvider{
		Provider: p,
		baseURL:  baseURL,
	}
	a.Dir = whmux.Dir{
		"login":    whmux.Exact(http.HandlerFunc(a.login)),
		"callback": whmux.Exact(http.HandlerFunc(a.callback)),
	}
	return a
}

func (a *AuthProvider) login(w http.ResponseWriter, r *http.Request) {
	ctx := whcompat.Context(r)
	state := newState()
	sess, err := a.Provider.BeginAuth(state)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	session, err := whsess.Load(ctx, a.sessionNamespace)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	session.Values["state"] = state
	session.Values["auth"] = sess.Marshal()
	err = session.Save(w)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	whredir.Redirect(w, r, url)
}

func (a *AuthProvider) callback(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}

func (a *AuthProvider) LoginURL(redirectTo string) string {
	return a.baseURL + "/login?" + url.Values{
		"redirect_to": {redirectTo}}.Encode()
}

type AuthProviders struct {
	baseURL   string
	providers []*AuthProvider

	whmux.Dir
}

func NewAuthProviders(baseURL, sessionNamespace string,
	providers ...goth.Provider) (a *AuthProviders) {
	p := make([]*AuthProvider, 0, len(providers))
	pMux := make(whmux.Dir, len(providers))
	for _, provider := range providers {
		w := newAuthProvider(provider,
			baseURL+"/provider/"+provider.Name(),
			sessionNamespace+"."+provider.Name())
		p = append(p, w)
		pMux[provider.Name()] = w
	}
	a = &AuthProviders{
		baseURL:   baseURL,
		providers: p,
	}
	a.Dir = whmux.Dir{
		"logout":   whmux.Exact(http.HandlerFunc(a.logout)),
		"provider": pMux,
	}
	return a
}

func (a *AuthProviders) logout(w http.ResponseWriter, r *http.Request) {
	panic("TODO")
}

func (a *AuthProviders) Providers() []*AuthProvider {
	return a.providers
}

func (a *AuthProviders) User(ctx context.Context) (*goth.User, error) {
	// TODO: make sure user.UserId and user.Provider are set and unique
	return nil, nil
}

func (a *AuthProviders) RequireUser(
	authorizedHandler, unauthorizedHandler http.Handler) http.Handler {
	return whroute.HandlerFunc(authorizedHandler,
		func(w http.ResponseWriter, r *http.Request) {
			u, err := a.User(whcompat.Context(r))
			if err != nil {
				wherr.Handle(w, r, err)
				return
			}
			if u == nil {
				unauthorizedHandler.ServeHTTP(w, r)
			} else {
				authorizedHandler.ServeHTTP(w, r)
			}
		})
}

func (a *AuthProviders) LogoutURL(redirectTo string) string {
	return a.baseURL + "/logout?" + url.Values{
		"redirect_to": {redirectTo}}.Encode()
}

func newState() string {
	var p [16]byte
	_, err := rand.Read(p[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(p[:])
}
