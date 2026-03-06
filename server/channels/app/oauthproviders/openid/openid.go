// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package oauthopenid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

const (
	discoveryHTTPTimeout = 10 * time.Second
	idTokenVerifyTimeout = 10 * time.Second

	// openIDScope is the scope an IdP requires before it issues an ID token.
	openIDScope = "openid"
)

// discoveryDocument is the subset of the OpenID Connect discovery document we use.
type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// resolvedIdP bundles a discovery document with the verifier built from it. Both live
// behind a single atomic pointer so that a reader can never pair one configuration's
// verifier with another configuration's cache key. A nil verifier marks a configuration
// without a DiscoveryEndpoint, where ID tokens cannot be verified at all.
type resolvedIdP struct {
	key      string
	doc      discoveryDocument
	verifier *oidc.IDTokenVerifier
}

type OpenIDProvider struct {
	mu    sync.Mutex
	cache map[string]*resolvedIdP // guarded by mu

	// active is the identity provider resolved by the most recent GetSSOSettings call,
	// which the OAuth flow always performs before handing us an ID token.
	active atomic.Pointer[resolvedIdP]
}

// OpenIDUser represents the standard OpenID Connect claims
// Compatible with Keycloak and other OIDC providers
type OpenIDUser struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	// EmailVerified is a pointer so we can distinguish "claim absent" (accept) from "claim=false" (reject).
	EmailVerified     *bool  `json:"email_verified,omitempty"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

func init() {
	provider := &OpenIDProvider{}
	einterfaces.RegisterOAuthProvider(model.ServiceOpenid, provider)
}

func userFromOpenIDUser(logger mlog.LoggerIFace, oiu *OpenIDUser, settings *model.SSOSettings) *model.User {
	user := &model.User{}

	var username string
	if settings != nil && model.SafeDereference(settings.UsePreferredUsername) && oiu.PreferredUsername != "" {
		// Split by "@" to match the email-prefix convention used elsewhere, in case
		// the IdP exposes preferred_username as an email-like value.
		username = strings.Split(oiu.PreferredUsername, "@")[0]
	} else if oiu.Email != "" {
		username = strings.Split(oiu.Email, "@")[0]
	}
	user.Username = model.CleanUsername(logger, username)

	user.FirstName = oiu.GivenName
	user.LastName = oiu.FamilyName

	// If given/family name not set, try to split full name
	if user.FirstName == "" && user.LastName == "" && oiu.Name != "" {
		if first, last, ok := strings.Cut(oiu.Name, " "); ok {
			user.FirstName = first
			user.LastName = last
		} else {
			user.FirstName = oiu.Name
		}
	}

	user.Email = strings.ToLower(oiu.Email)
	user.AuthData = &oiu.Sub
	user.AuthService = model.ServiceOpenid

	return user
}

func openIDUserFromJSON(data io.Reader) (*OpenIDUser, error) {
	decoder := json.NewDecoder(data)
	var oiu OpenIDUser
	err := decoder.Decode(&oiu)
	if err != nil {
		return nil, err
	}
	return &oiu, nil
}

func (oiu *OpenIDUser) IsValid() error {
	if oiu.Sub == "" {
		return errors.New("user sub (subject) claim is required")
	}

	if oiu.Email == "" {
		return errors.New("user email claim is required")
	}

	// Reject only when the IdP explicitly signals an unverified email.
	// If the claim is absent (nil), accept — many IdPs omit it.
	if oiu.EmailVerified != nil && !*oiu.EmailVerified {
		return errors.New("user email is not verified by the identity provider")
	}

	return nil
}

// GetUserFromJSON builds the Mattermost user from the UserInfo response. When the OAuth
// flow verified an ID token beforehand, tokenUser carries its subject: the UserInfo
// response itself is only authenticated by a bearer token, so binding the two subjects
// together makes sure the profile we import belongs to the identity the IdP signed for.
func (op *OpenIDProvider) GetUserFromJSON(rctx request.CTX, data io.Reader, tokenUser *model.User, settings *model.SSOSettings) (*model.User, error) {
	oiu, err := openIDUserFromJSON(data)
	if err != nil {
		return nil, err
	}
	if err = oiu.IsValid(); err != nil {
		return nil, err
	}

	if tokenUser != nil && tokenUser.AuthData != nil && *tokenUser.AuthData != oiu.Sub {
		return nil, errors.New("UserInfo subject does not match the verified ID token subject")
	}

	return userFromOpenIDUser(rctx.Logger(), oiu, settings), nil
}

// GetSSOSettings returns the settings of the requested service with the OAuth endpoints
// filled in from the provider's discovery document. Resolving them here is what makes a
// DiscoveryEndpoint-only configuration work: the admin console does not expose the
// authorization, token and userinfo endpoints for OpenID and actively clears them, yet
// the surrounding OAuth flow dereferences all three.
//
// It also caches the resolved provider for the ID token verification that follows in the
// same request.
func (op *OpenIDProvider) GetSSOSettings(rctx request.CTX, config *model.Config, service string) (*model.SSOSettings, error) {
	settings := config.GetSSOService(service)
	if settings == nil {
		return nil, fmt.Errorf("no SSO settings configured for service %q", service)
	}

	discoveryEndpoint := model.SafeDereference(settings.DiscoveryEndpoint)
	if discoveryEndpoint == "" {
		// Without a discovery document we do not know the IdP's JWKS location, so ID
		// tokens cannot be verified. Record that explicitly rather than leaving a
		// previously resolved provider active, which would verify this service's
		// tokens against another IdP's keys.
		op.active.Store(&resolvedIdP{key: "no-discovery|" + service})
		return settings, nil
	}

	idp, err := op.resolveIdP(rctx, settings)
	if err != nil {
		// Endpoints configured explicitly are enough to run the OAuth flow, so a
		// discovery outage only fails the request when we have nothing to fall back on.
		if hasExplicitEndpoints(settings) {
			rctx.Logger().Warn("OpenID: discovery lookup failed, falling back to the explicitly configured endpoints",
				mlog.String("service", service),
				mlog.Err(err),
			)
			op.active.Store(&resolvedIdP{key: "no-discovery|" + service})
			return settings, nil
		}
		return nil, err
	}

	return withDiscoveredEndpoints(settings, idp.doc), nil
}

// GetUserFromIdToken verifies the OIDC ID token's signature against the JWKS published by the
// configured DiscoveryEndpoint and validates the iss, aud and exp claims. Returns an error if
// verification fails so the surrounding OAuth flow rejects the login. The returned user carries
// only the verified subject; profile attributes are sourced from the UserInfo endpoint in
// GetUserFromJSON, which cross-checks its subject against this one.
func (op *OpenIDProvider) GetUserFromIdToken(rctx request.CTX, idToken string) (*model.User, error) {
	idp := op.active.Load()
	if idp == nil {
		return nil, errors.New("OpenID identity provider not resolved; cannot verify ID token")
	}
	if idp.verifier == nil {
		rctx.Logger().Warn("OpenID: accepting ID token without verification because no DiscoveryEndpoint is configured")
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), idTokenVerifyTimeout)
	defer cancel()

	verified, err := idp.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("OpenID ID token verification failed: %w", err)
	}
	if verified.Subject == "" {
		return nil, errors.New("OpenID ID token is missing the sub (subject) claim")
	}

	sub := verified.Subject
	return &model.User{
		AuthData:    &sub,
		AuthService: model.ServiceOpenid,
	}, nil
}

func (op *OpenIDProvider) IsSameUser(_ request.CTX, dbUser, oauthUser *model.User) bool {
	return dbUser.AuthData != nil && oauthUser.AuthData != nil && *dbUser.AuthData == *oauthUser.AuthData
}

// resolveIdP returns the discovery document and ID token verifier for the given settings,
// fetching the discovery document at most once per configuration.
func (op *OpenIDProvider) resolveIdP(rctx request.CTX, settings *model.SSOSettings) (*resolvedIdP, error) {
	discoveryEndpoint := model.SafeDereference(settings.DiscoveryEndpoint)
	clientID := model.SafeDereference(settings.Id)
	if clientID == "" {
		return nil, errors.New("OpenID ClientID (Id) must be configured to verify ID tokens")
	}

	key := discoveryEndpoint + "|" + clientID

	if idp := op.active.Load(); idp != nil && idp.key == key {
		return idp, nil
	}

	op.mu.Lock()
	defer op.mu.Unlock()

	if idp, ok := op.cache[key]; ok {
		op.active.Store(idp)
		return idp, nil
	}

	if !strings.Contains(model.SafeDereference(settings.Scope), openIDScope) {
		rctx.Logger().Warn("OpenID: configured scope does not request the \"openid\" scope, so the identity provider will not issue ID tokens and logins cannot be verified",
			mlog.String("scope", model.SafeDereference(settings.Scope)),
		)
	}

	doc, err := fetchDiscoveryDocument(discoveryEndpoint)
	if err != nil {
		return nil, err
	}

	rctx.Logger().Debug("OpenID: initialized ID token verifier",
		mlog.String("issuer", doc.Issuer),
		mlog.String("jwks_uri", doc.JWKSURI),
	)

	// Use Background context for the key set so its lifetime isn't tied to a single request.
	httpClient := &http.Client{Timeout: discoveryHTTPTimeout}
	keySet := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), httpClient), doc.JWKSURI)

	idp := &resolvedIdP{
		key:      key,
		doc:      *doc,
		verifier: oidc.NewVerifier(doc.Issuer, keySet, &oidc.Config{ClientID: clientID}),
	}

	if op.cache == nil {
		op.cache = make(map[string]*resolvedIdP)
	}
	op.cache[key] = idp
	op.active.Store(idp)

	return idp, nil
}

func fetchDiscoveryDocument(discoveryEndpoint string) (*discoveryDocument, error) {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryHTTPTimeout)
	defer cancel()

	httpClient := &http.Client{Timeout: discoveryHTTPTimeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OpenID discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenID discovery document returned status %d", resp.StatusCode)
	}

	var doc discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding OpenID discovery document: %w", err)
	}
	if doc.Issuer == "" || doc.JWKSURI == "" {
		return nil, errors.New("OpenID discovery document missing issuer or jwks_uri")
	}
	// The OAuth flow dereferences all three endpoints, so a document that omits one is
	// only usable if the admin configured that endpoint explicitly.
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.UserInfoEndpoint == "" {
		return nil, errors.New("OpenID discovery document missing authorization_endpoint, token_endpoint or userinfo_endpoint")
	}

	return &doc, nil
}

// withDiscoveredEndpoints returns a copy of settings with any endpoint the admin left
// empty filled in from the discovery document. Explicitly configured endpoints win, so
// an existing deployment that set them by hand keeps working unchanged.
func withDiscoveredEndpoints(settings *model.SSOSettings, doc discoveryDocument) *model.SSOSettings {
	resolved := *settings

	if model.SafeDereference(resolved.AuthEndpoint) == "" {
		resolved.AuthEndpoint = &doc.AuthorizationEndpoint
	}
	if model.SafeDereference(resolved.TokenEndpoint) == "" {
		resolved.TokenEndpoint = &doc.TokenEndpoint
	}
	if model.SafeDereference(resolved.UserAPIEndpoint) == "" {
		resolved.UserAPIEndpoint = &doc.UserInfoEndpoint
	}

	return &resolved
}

func hasExplicitEndpoints(settings *model.SSOSettings) bool {
	return model.SafeDereference(settings.AuthEndpoint) != "" &&
		model.SafeDereference(settings.TokenEndpoint) != "" &&
		model.SafeDereference(settings.UserAPIEndpoint) != ""
}
