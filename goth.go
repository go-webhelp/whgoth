// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

package whgoth // import "gopkg.in/go-webhelp/whgoth.v1"

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/markbates/goth"
	"github.com/spacemonkeygo/errors"
	"golang.org/x/net/context"
	"gopkg.in/webhelp.v1"
	"gopkg.in/webhelp.v1/whcache"
	"gopkg.in/webhelp.v1/whcompat"
	"gopkg.in/webhelp.v1/wherr"
	"gopkg.in/webhelp.v1/whmux"
	"gopkg.in/webhelp.v1/whredir"
	"gopkg.in/webhelp.v1/whroute"
	"gopkg.in/webhelp.v1/whsess"
)

var (
	userKey      = webhelp.GenSym()
	providerName = whmux.NewStringArg()
)

type AuthProvider struct {
	goth.Provider
	baseURL          string
	sessionNamespace string
}

func newAuthProvider(p goth.Provider, baseURL, sessionNamespace string) (
	a *AuthProvider) {
	return &AuthProvider{
		Provider:         p,
		baseURL:          baseURL,
		sessionNamespace: sessionNamespace,
	}
}

func (a *AuthProvider) login(w http.ResponseWriter, r *http.Request) {
	ctx := whcompat.Context(r)

	u, err := a.User(ctx)
	if err == nil && u != nil {
		whredir.Redirect(w, r, safeRedirect(r.FormValue("redirect_to"), "/"))
		return
	}

	state := newState()
	sess, err := a.Provider.BeginAuthCtx(ctx, state)
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
	for key := range session.Values {
		delete(session.Values, key)
	}
	session.Values["state"] = state
	session.Values["logged_in"] = false
	session.Values["redirect_to"] = safeRedirect(r.FormValue("redirect_to"), "/")
	session.Values["auth"] = sess.Marshal()
	err = session.Save(ctx, w)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	whredir.Redirect(w, r, url)
}

func (a *AuthProvider) Logout(ctx context.Context, w http.ResponseWriter) (
	err error) {
	session, err := whsess.Load(ctx, a.sessionNamespace)
	if err != nil {
		return err
	}
	return session.Clear(ctx, w)
}

func (a *AuthProvider) callback(w http.ResponseWriter, r *http.Request) {
	ctx := whcompat.Context(r)
	session, err := whsess.Load(ctx, a.sessionNamespace)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	if loggedIn, _ := session.Values["logged_in"].(bool); loggedIn {
		wherr.Handle(w, r, wherr.BadRequest.New("already logged in"))
		return
	}

	auth, ok := session.Values["auth"].(string)
	if !ok {
		wherr.Handle(w, r, wherr.InternalServerError.New(
			"no existing session found"))
		return
	}

	sess, err := a.Provider.UnmarshalSession(auth)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	authToken, err := sess.AuthorizeCtx(ctx, a.Provider, r.URL.Query())
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	redirectTo, _ := session.Values["redirect_to"].(string)
	session.Values["auth_token"] = authToken
	session.Values["logged_in"] = true
	session.Values["redirect_to"] = nil
	session.Values["auth"] = sess.Marshal()
	err = session.Save(ctx, w)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	whredir.Redirect(w, r, safeRedirect(redirectTo, "/"))
}

func (a *AuthProvider) User(ctx context.Context) (*goth.User, error) {
	session, err := whsess.Load(ctx, a.sessionNamespace)
	if err != nil {
		return nil, err
	}

	if loggedIn, _ := session.Values["logged_in"].(bool); !loggedIn {
		return nil, nil
	}

	auth, ok := session.Values["auth"].(string)
	if !ok {
		return nil, nil
	}

	sess, err := a.Provider.UnmarshalSession(auth)
	if err != nil {
		log.Printf("failed to unmarshal session: %v", err)
		return nil, nil
	}

	u, err := a.Provider.FetchUserCtx(ctx, sess)
	if err != nil {
		log.Printf("failed to fetch user: %v", err)
		return nil, nil
	}

	if u.UserID == "" || u.Provider == "" {
		log.Printf("user had no user id or provider set")
		return nil, nil
	}
	return &u, nil
}

func (a *AuthProvider) LoginURL(redirectTo string) string {
	return a.baseURL + "/login?" + url.Values{
		"redirect_to": {redirectTo}}.Encode()
}

type AuthProviders struct {
	baseURL, sessionNamespace string
	providersCallback         func(context.Context) ([]goth.Provider, error)
	whmux.Dir

	providersMtx    sync.Mutex
	providersSetup  bool
	providers       []*AuthProvider
	providersByName map[string]*AuthProvider
}

func NewAuthProviders(baseURL, sessionNamespace string,
	providers ...goth.Provider) (a *AuthProviders) {
	return NewLazyAuthProviders(baseURL, sessionNamespace,
		func(context.Context) ([]goth.Provider, error) {
			return providers, nil
		})
}

func NewLazyAuthProviders(baseURL, sessionNamespace string,
	providers func(context.Context) ([]goth.Provider, error)) (
	a *AuthProviders) {

	a = &AuthProviders{
		baseURL:           baseURL,
		sessionNamespace:  sessionNamespace,
		providersCallback: providers,
	}
	a.Dir = whmux.Dir{
		"logout": whmux.Exact(http.HandlerFunc(a.logout)),
		"provider": providerName.Shift(whmux.Dir{
			"login":    whmux.Exact(http.HandlerFunc(a.login)),
			"callback": whmux.Exact(http.HandlerFunc(a.callback)),
		}),
	}
	return a
}

func (a *AuthProviders) setupProviders(ctx context.Context) error {
	a.providersMtx.Lock()
	defer a.providersMtx.Unlock()
	if a.providersSetup {
		return nil
	}

	providers, err := a.providersCallback(ctx)
	if err != nil {
		return err
	}

	p := make([]*AuthProvider, 0, len(providers))
	providersByName := make(map[string]*AuthProvider, len(providers))
	for _, provider := range providers {
		w := newAuthProvider(provider,
			a.baseURL+"/provider/"+provider.Name(),
			a.sessionNamespace+"."+provider.Name())
		p = append(p, w)
		if provider.Name() != "" {
			providersByName[provider.Name()] = w
		}
	}
	a.providers = p
	a.providersByName = providersByName
	a.providersSetup = true

	return nil
}

func (a *AuthProviders) login(w http.ResponseWriter, r *http.Request) {
	ctx := whcompat.Context(r)
	err := a.setupProviders(ctx)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	name := providerName.Get(ctx)
	if p, ok := a.providersByName[name]; ok {
		p.login(w, r)
	} else {
		wherr.Handle(w, r, wherr.NotFound.New("provider %s not found", name))
	}
}

func (a *AuthProviders) callback(w http.ResponseWriter, r *http.Request) {
	ctx := whcompat.Context(r)
	err := a.setupProviders(ctx)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}

	name := providerName.Get(ctx)
	if p, ok := a.providersByName[name]; ok {
		p.callback(w, r)
	} else {
		wherr.Handle(w, r, wherr.NotFound.New("provider %s not found", name))
	}
}

func (a *AuthProviders) Logout(ctx context.Context, w http.ResponseWriter) (
	err error) {
	err = a.setupProviders(ctx)
	if err != nil {
		return err
	}

	var errs errors.ErrorGroup
	for _, provider := range a.providers {
		errs.Add(provider.Logout(ctx, w))
	}
	return errs.Finalize()
}

func (a *AuthProviders) logout(w http.ResponseWriter, r *http.Request) {
	err := a.Logout(whcompat.Context(r), w)
	if err != nil {
		wherr.Handle(w, r, err)
		return
	}
	whredir.Redirect(w, r, safeRedirect(r.FormValue("redirect_to"), "/"))
}

func safeRedirect(redirectTo, def string) string {
	u, err := url.Parse(redirectTo)
	if err != nil {
		return def
	}
	if u.RawQuery == "" {
		if u.Path == "" {
			return def
		}
		return u.Path
	}
	return u.Path + "?" + u.RawQuery
}

func (a *AuthProviders) Providers(ctx context.Context) (
	[]*AuthProvider, error) {
	err := a.setupProviders(ctx)
	if err != nil {
		return nil, err
	}

	return a.providers, nil
}

func (a *AuthProviders) User(ctx context.Context) (*goth.User, error) {
	if u, ok := whcache.Get(ctx, userKey).(*goth.User); ok && u != nil {
		return u, nil
	}
	err := a.setupProviders(ctx)
	if err != nil {
		return nil, err
	}

	for _, provider := range a.providers {
		u, err := provider.User(ctx)
		if err != nil || u != nil {
			whcache.Set(ctx, userKey, u)
			return u, err
		}
	}
	return nil, nil
}

func (a *AuthProviders) RequireUser(
	authorizedHandler, unauthorizedHandler http.Handler) http.Handler {
	return whroute.HandlerFunc(authorizedHandler,
		func(w http.ResponseWriter, r *http.Request) {
			ctx := whcompat.Context(r)
			u, err := a.User(ctx)
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
