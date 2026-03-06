// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package oauthopenid

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeyID = "test-key"

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }

// testIdP is an in-process identity provider serving a discovery document and a JWKS
// containing the public half of the key it signs ID tokens with.
type testIdP struct {
	*httptest.Server
	key           *rsa.PrivateKey
	discoveryHits atomic.Int64
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idp := &testIdP{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		idp.discoveryHits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 idp.URL,
			"authorization_endpoint": idp.URL + "/auth",
			"token_endpoint":         idp.URL + "/token",
			"userinfo_endpoint":      idp.URL + "/userinfo",
			"jwks_uri":               idp.URL + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": testKeyID,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})

	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)
	return idp
}

func (idp *testIdP) discoveryEndpoint() string {
	return idp.URL + "/.well-known/openid-configuration"
}

// signIDToken produces an RS256 JWT. signingKey allows signing with a key the IdP does
// not publish, to prove that verification actually checks the signature.
func signIDToken(t *testing.T, signingKey *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	segment := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	signingInput := segment(map[string]any{"alg": "RS256", "typ": "JWT", "kid": testKeyID}) +
		"." + segment(claims)

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, digest[:])
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (idp *testIdP) idToken(t *testing.T, clientID, subject string) string {
	t.Helper()
	return signIDToken(t, idp.key, map[string]any{
		"iss": idp.URL,
		"aud": clientID,
		"sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
}

// openIDConfig returns a config whose OpenIdSettings point at the given IdP.
func openIDConfig(idp *testIdP, clientID string) *model.Config {
	return &model.Config{
		OpenIdSettings: model.SSOSettings{
			Enable:            boolPtr(true),
			Id:                strPtr(clientID),
			Scope:             strPtr(model.OpenidSettingsDefaultScope),
			DiscoveryEndpoint: strPtr(idp.discoveryEndpoint()),
			AuthEndpoint:      strPtr(""),
			TokenEndpoint:     strPtr(""),
			UserAPIEndpoint:   strPtr(""),
		},
	}
}

func TestOpenIDUserFromJSON(t *testing.T) {
	rctx := request.TestContext(t)
	provider := &OpenIDProvider{}

	t.Run("valid user", func(t *testing.T) {
		oiu := OpenIDUser{
			Sub:               "abc-123",
			Email:             "test@example.com",
			PreferredUsername: "testuser",
			Name:              "Test User",
		}
		b, err := json.Marshal(oiu)
		require.NoError(t, err)

		user, err := provider.GetUserFromJSON(rctx, bytes.NewReader(b), nil, nil)
		require.NoError(t, err)
		require.NotNil(t, user.AuthData)
		assert.Equal(t, "abc-123", *user.AuthData)
		assert.Equal(t, model.ServiceOpenid, user.AuthService)
	})

	t.Run("empty body should fail validation", func(t *testing.T) {
		_, err := provider.GetUserFromJSON(rctx, strings.NewReader("{}"), nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user sub")
	})

	t.Run("invalid json", func(t *testing.T) {
		_, err := provider.GetUserFromJSON(rctx, strings.NewReader("invalid json"), nil, nil)
		require.Error(t, err)
	})

	t.Run("email_verified=false rejected", func(t *testing.T) {
		oiu := OpenIDUser{
			Sub:           "abc-123",
			Email:         "test@example.com",
			EmailVerified: boolPtr(false),
		}
		b, err := json.Marshal(oiu)
		require.NoError(t, err)

		_, err = provider.GetUserFromJSON(rctx, bytes.NewReader(b), nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not verified")
	})
}

func TestGetUserFromJSONSubjectBinding(t *testing.T) {
	rctx := request.TestContext(t)
	provider := &OpenIDProvider{}

	userInfo, err := json.Marshal(OpenIDUser{Sub: "abc-123", Email: "test@example.com"})
	require.NoError(t, err)

	t.Run("matching subject accepted", func(t *testing.T) {
		tokenUser := &model.User{AuthData: strPtr("abc-123")}
		user, err := provider.GetUserFromJSON(rctx, bytes.NewReader(userInfo), tokenUser, nil)
		require.NoError(t, err)
		assert.Equal(t, "abc-123", *user.AuthData)
	})

	t.Run("mismatched subject rejected", func(t *testing.T) {
		tokenUser := &model.User{AuthData: strPtr("someone-else")}
		_, err := provider.GetUserFromJSON(rctx, bytes.NewReader(userInfo), tokenUser, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the verified ID token subject")
	})

	t.Run("no token user accepted", func(t *testing.T) {
		_, err := provider.GetUserFromJSON(rctx, bytes.NewReader(userInfo), nil, nil)
		require.NoError(t, err)
	})
}

func TestOpenIDUserIsValid(t *testing.T) {
	testCases := []struct {
		description string
		user        OpenIDUser
		isValid     bool
		expectedErr string
	}{
		{"valid user", OpenIDUser{Sub: "s", Email: "e@x.com"}, true, ""},
		{"empty sub", OpenIDUser{Sub: "", Email: "e@x.com"}, false, "user sub (subject) claim is required"},
		{"empty email", OpenIDUser{Sub: "s", Email: ""}, false, "user email claim is required"},
		{"email_verified nil", OpenIDUser{Sub: "s", Email: "e@x.com", EmailVerified: nil}, true, ""},
		{"email_verified true", OpenIDUser{Sub: "s", Email: "e@x.com", EmailVerified: boolPtr(true)}, true, ""},
		{"email_verified false", OpenIDUser{Sub: "s", Email: "e@x.com", EmailVerified: boolPtr(false)}, false, "user email is not verified by the identity provider"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			err := tc.user.IsValid()
			if tc.isValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.expectedErr, err.Error())
			}
		})
	}
}

func TestUserFromOpenIDUser(t *testing.T) {
	logger := mlog.CreateConsoleTestLogger(t)

	testCases := []struct {
		description          string
		openIDUser           OpenIDUser
		usePreferredUsername bool
		settingsNil          bool
		expectedUsername     string
		expectedFirstName    string
		expectedLastName     string
		expectedEmail        string
		expectedAuthData     string
	}{
		{
			description: "PreferredUsername used when UsePreferredUsername=true",
			openIDUser: OpenIDUser{
				Sub:               "1",
				Email:             "test@example.com",
				PreferredUsername: "preferred.user",
				Name:              "First Last",
			},
			usePreferredUsername: true,
			expectedUsername:     "preferred.user",
			expectedFirstName:    "First",
			expectedLastName:     "Last",
			expectedEmail:        "test@example.com",
			expectedAuthData:     "1",
		},
		{
			description: "Email prefix used when UsePreferredUsername=false",
			openIDUser: OpenIDUser{
				Sub:               "2",
				Email:             "jane.doe@example.com",
				PreferredUsername: "preferred.user",
				Name:              "Jane Doe",
			},
			usePreferredUsername: false,
			expectedUsername:     "jane.doe",
			expectedFirstName:    "Jane",
			expectedLastName:     "Doe",
			expectedEmail:        "jane.doe@example.com",
			expectedAuthData:     "2",
		},
		{
			description: "Email prefix used when settings is nil (default behavior)",
			openIDUser: OpenIDUser{
				Sub:               "3",
				Email:             "alice@example.com",
				PreferredUsername: "preferred.user",
				Name:              "Alice Wonder",
			},
			settingsNil:       true,
			expectedUsername:  "alice",
			expectedFirstName: "Alice",
			expectedLastName:  "Wonder",
			expectedEmail:     "alice@example.com",
			expectedAuthData:  "3",
		},
		{
			description: "Email prefix fallback when PreferredUsername empty and UsePreferredUsername=true",
			openIDUser: OpenIDUser{
				Sub:   "4",
				Email: "bob@example.com",
				Name:  "Bob Builder",
			},
			usePreferredUsername: true,
			expectedUsername:     "bob",
			expectedFirstName:    "Bob",
			expectedLastName:     "Builder",
			expectedEmail:        "bob@example.com",
			expectedAuthData:     "4",
		},
		{
			description: "GivenName/FamilyName preferred over Name",
			openIDUser: OpenIDUser{
				Sub:        "5",
				Email:      "carol@example.com",
				GivenName:  "Carol",
				FamilyName: "Smith",
				Name:       "Ignored Name",
			},
			usePreferredUsername: false,
			expectedUsername:     "carol",
			expectedFirstName:    "Carol",
			expectedLastName:     "Smith",
			expectedEmail:        "carol@example.com",
			expectedAuthData:     "5",
		},
		{
			description: "Name with multiple parts split into first + rest",
			openIDUser: OpenIDUser{
				Sub:   "6",
				Email: "long@example.com",
				Name:  "First Middle Van Der Last",
			},
			usePreferredUsername: false,
			expectedUsername:     "long",
			expectedFirstName:    "First",
			expectedLastName:     "Middle Van Der Last",
			expectedEmail:        "long@example.com",
			expectedAuthData:     "6",
		},
		{
			description: "Single-name fallback",
			openIDUser: OpenIDUser{
				Sub:   "7",
				Email: "mono@example.com",
				Name:  "Mononym",
			},
			usePreferredUsername: false,
			expectedUsername:     "mono",
			expectedFirstName:    "Mononym",
			expectedLastName:     "",
			expectedEmail:        "mono@example.com",
			expectedAuthData:     "7",
		},
		{
			description: "Email lowercased",
			openIDUser: OpenIDUser{
				Sub:        "8",
				Email:      "UPPER@EXAMPLE.COM",
				GivenName:  "Upper",
				FamilyName: "Case",
			},
			usePreferredUsername: false,
			expectedUsername:     "upper",
			expectedFirstName:    "Upper",
			expectedLastName:     "Case",
			expectedEmail:        "upper@example.com",
			expectedAuthData:     "8",
		},
		{
			description: "PreferredUsername cleaned",
			openIDUser: OpenIDUser{
				Sub:               "9",
				Email:             "clean@example.com",
				PreferredUsername: "weird@@user!!",
				GivenName:         "Weird",
				FamilyName:        "Name",
			},
			usePreferredUsername: true,
			expectedUsername:     "weird",
			expectedFirstName:    "Weird",
			expectedLastName:     "Name",
			expectedEmail:        "clean@example.com",
			expectedAuthData:     "9",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			var settings *model.SSOSettings
			if !tc.settingsNil {
				settings = &model.SSOSettings{
					UsePreferredUsername: boolPtr(tc.usePreferredUsername),
				}
			}

			user := userFromOpenIDUser(logger, &tc.openIDUser, settings)

			require.NotNil(t, user)
			assert.Equal(t, tc.expectedUsername, user.Username)
			assert.Equal(t, tc.expectedFirstName, user.FirstName)
			assert.Equal(t, tc.expectedLastName, user.LastName)
			assert.Equal(t, tc.expectedEmail, user.Email)
			require.NotNil(t, user.AuthData)
			assert.Equal(t, tc.expectedAuthData, *user.AuthData)
			assert.Equal(t, model.ServiceOpenid, user.AuthService)
		})
	}
}

func TestGetSSOSettingsUsesRequestedService(t *testing.T) {
	rctx := request.TestContext(t)

	openIDIdP := newTestIdP(t)
	googleIdP := newTestIdP(t)

	cfg := openIDConfig(openIDIdP, "openid-client")
	cfg.GoogleSettings = model.SSOSettings{
		Enable:            boolPtr(true),
		Id:                strPtr("google-client"),
		Scope:             strPtr(model.OpenidSettingsDefaultScope),
		DiscoveryEndpoint: strPtr(googleIdP.discoveryEndpoint()),
		AuthEndpoint:      strPtr(""),
		TokenEndpoint:     strPtr(""),
		UserAPIEndpoint:   strPtr(""),
	}

	provider := &OpenIDProvider{}

	t.Run("google resolves against the google settings", func(t *testing.T) {
		settings, err := provider.GetSSOSettings(rctx, cfg, model.ServiceGoogle)
		require.NoError(t, err)
		assert.Equal(t, "google-client", *settings.Id)
		assert.Equal(t, googleIdP.URL+"/token", *settings.TokenEndpoint)
		assert.Equal(t, googleIdP.URL+"/userinfo", *settings.UserAPIEndpoint)
	})

	t.Run("openid resolves against the openid settings", func(t *testing.T) {
		settings, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.NoError(t, err)
		assert.Equal(t, "openid-client", *settings.Id)
		assert.Equal(t, openIDIdP.URL+"/token", *settings.TokenEndpoint)
	})

	t.Run("unknown service is rejected", func(t *testing.T) {
		_, err := provider.GetSSOSettings(rctx, cfg, "not-a-service")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not-a-service")
	})
}

func TestGetSSOSettingsResolvesEndpoints(t *testing.T) {
	rctx := request.TestContext(t)

	t.Run("endpoints filled in from the discovery document", func(t *testing.T) {
		idp := newTestIdP(t)
		provider := &OpenIDProvider{}

		settings, err := provider.GetSSOSettings(rctx, openIDConfig(idp, "client-id"), model.ServiceOpenid)
		require.NoError(t, err)
		assert.Equal(t, idp.URL+"/auth", *settings.AuthEndpoint)
		assert.Equal(t, idp.URL+"/token", *settings.TokenEndpoint)
		assert.Equal(t, idp.URL+"/userinfo", *settings.UserAPIEndpoint)
	})

	t.Run("explicitly configured endpoints win", func(t *testing.T) {
		idp := newTestIdP(t)
		cfg := openIDConfig(idp, "client-id")
		cfg.OpenIdSettings.AuthEndpoint = strPtr("https://explicit.example.com/auth")
		provider := &OpenIDProvider{}

		settings, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.NoError(t, err)
		assert.Equal(t, "https://explicit.example.com/auth", *settings.AuthEndpoint)
		assert.Equal(t, idp.URL+"/token", *settings.TokenEndpoint, "endpoints left empty still come from discovery")
	})

	t.Run("config changes are picked up even while the discovery document is cached", func(t *testing.T) {
		idp := newTestIdP(t)
		cfg := openIDConfig(idp, "client-id")
		provider := &OpenIDProvider{}

		_, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.NoError(t, err)

		cfg.OpenIdSettings.Secret = strPtr("rotated-secret")
		settings, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.NoError(t, err)
		assert.Equal(t, "rotated-secret", *settings.Secret)
		assert.Equal(t, int64(1), idp.discoveryHits.Load())
	})

	t.Run("without a discovery endpoint the settings are returned unchanged", func(t *testing.T) {
		cfg := &model.Config{OpenIdSettings: model.SSOSettings{
			Enable:            boolPtr(true),
			Id:                strPtr("client-id"),
			Scope:             strPtr(model.OpenidSettingsDefaultScope),
			DiscoveryEndpoint: strPtr(""),
			AuthEndpoint:      strPtr("https://idp.example.com/auth"),
			TokenEndpoint:     strPtr("https://idp.example.com/token"),
			UserAPIEndpoint:   strPtr("https://idp.example.com/userinfo"),
		}}
		provider := &OpenIDProvider{}

		settings, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com/auth", *settings.AuthEndpoint)

		// Without a JWKS location ID tokens cannot be verified, so the flow proceeds
		// on the strength of the code exchange alone rather than failing.
		user, err := provider.GetUserFromIdToken(rctx, "any.id.token")
		require.NoError(t, err)
		assert.Nil(t, user)
	})

	t.Run("discovery outage falls back to explicit endpoints", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		cfg := &model.Config{OpenIdSettings: model.SSOSettings{
			Enable:            boolPtr(true),
			Id:                strPtr("client-id"),
			Scope:             strPtr(model.OpenidSettingsDefaultScope),
			DiscoveryEndpoint: strPtr(srv.URL),
			AuthEndpoint:      strPtr("https://idp.example.com/auth"),
			TokenEndpoint:     strPtr("https://idp.example.com/token"),
			UserAPIEndpoint:   strPtr("https://idp.example.com/userinfo"),
		}}
		provider := &OpenIDProvider{}

		settings, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com/token", *settings.TokenEndpoint)
	})

	t.Run("discovery outage without a fallback fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		cfg := &model.Config{OpenIdSettings: model.SSOSettings{
			Enable:            boolPtr(true),
			Id:                strPtr("client-id"),
			Scope:             strPtr(model.OpenidSettingsDefaultScope),
			DiscoveryEndpoint: strPtr(srv.URL),
			AuthEndpoint:      strPtr(""),
			TokenEndpoint:     strPtr(""),
			UserAPIEndpoint:   strPtr(""),
		}}
		provider := &OpenIDProvider{}

		_, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 500")
	})

	t.Run("missing client id is rejected", func(t *testing.T) {
		idp := newTestIdP(t)
		cfg := openIDConfig(idp, "")
		provider := &OpenIDProvider{}

		_, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ClientID")
	})
}

func TestGetSSOSettingsDiscoveryFailures(t *testing.T) {
	rctx := request.TestContext(t)

	newProviderFor := func(t *testing.T, handler http.HandlerFunc) (*OpenIDProvider, *model.Config) {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return &OpenIDProvider{}, &model.Config{OpenIdSettings: model.SSOSettings{
			Enable:            boolPtr(true),
			Id:                strPtr("client-id"),
			Scope:             strPtr(model.OpenidSettingsDefaultScope),
			DiscoveryEndpoint: strPtr(srv.URL),
			AuthEndpoint:      strPtr(""),
			TokenEndpoint:     strPtr(""),
			UserAPIEndpoint:   strPtr(""),
		}}
	}

	t.Run("non-200 response", func(t *testing.T) {
		provider, cfg := newProviderFor(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		})
		_, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 404")
	})

	t.Run("malformed JSON", func(t *testing.T) {
		provider, cfg := newProviderFor(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})
		_, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding")
	})

	t.Run("missing issuer or jwks_uri", func(t *testing.T) {
		provider, cfg := newProviderFor(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{})
		})
		_, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing issuer or jwks_uri")
	})

	t.Run("missing OAuth endpoints", func(t *testing.T) {
		provider, cfg := newProviderFor(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   "https://idp.example.com",
				"jwks_uri": "https://idp.example.com/jwks.json",
			})
		})
		_, err := provider.GetSSOSettings(rctx, cfg, model.ServiceOpenid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization_endpoint")
	})
}

func TestGetUserFromIdToken(t *testing.T) {
	rctx := request.TestContext(t)

	resolvedProvider := func(t *testing.T, idp *testIdP, clientID string) *OpenIDProvider {
		t.Helper()
		provider := &OpenIDProvider{}
		_, err := provider.GetSSOSettings(rctx, openIDConfig(idp, clientID), model.ServiceOpenid)
		require.NoError(t, err)
		return provider
	}

	t.Run("valid token yields the verified subject", func(t *testing.T) {
		idp := newTestIdP(t)
		provider := resolvedProvider(t, idp, "client-id")

		user, err := provider.GetUserFromIdToken(rctx, idp.idToken(t, "client-id", "user-1"))
		require.NoError(t, err)
		require.NotNil(t, user)
		require.NotNil(t, user.AuthData)
		assert.Equal(t, "user-1", *user.AuthData)
		assert.Equal(t, model.ServiceOpenid, user.AuthService)
	})

	t.Run("token for another audience is rejected", func(t *testing.T) {
		idp := newTestIdP(t)
		provider := resolvedProvider(t, idp, "client-id")

		_, err := provider.GetUserFromIdToken(rctx, idp.idToken(t, "another-client", "user-1"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("token signed by an unknown key is rejected", func(t *testing.T) {
		idp := newTestIdP(t)
		provider := resolvedProvider(t, idp, "client-id")

		attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		forged := signIDToken(t, attackerKey, map[string]any{
			"iss": idp.URL,
			"aud": "client-id",
			"sub": "user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		_, err = provider.GetUserFromIdToken(rctx, forged)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		idp := newTestIdP(t)
		provider := resolvedProvider(t, idp, "client-id")

		expired := signIDToken(t, idp.key, map[string]any{
			"iss": idp.URL,
			"aud": "client-id",
			"sub": "user-1",
			"exp": time.Now().Add(-time.Hour).Unix(),
		})

		_, err := provider.GetUserFromIdToken(rctx, expired)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("token from a different issuer is rejected", func(t *testing.T) {
		idp := newTestIdP(t)
		provider := resolvedProvider(t, idp, "client-id")

		wrongIssuer := signIDToken(t, idp.key, map[string]any{
			"iss": "https://evil.example.com",
			"aud": "client-id",
			"sub": "user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		_, err := provider.GetUserFromIdToken(rctx, wrongIssuer)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("garbage token is rejected", func(t *testing.T) {
		idp := newTestIdP(t)
		provider := resolvedProvider(t, idp, "client-id")

		_, err := provider.GetUserFromIdToken(rctx, "dummy.token.here")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("provider without resolved settings refuses to verify", func(t *testing.T) {
		provider := &OpenIDProvider{}
		_, err := provider.GetUserFromIdToken(rctx, "dummy.token.here")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not resolved")
	})
}

func TestResolveIdPCaching(t *testing.T) {
	rctx := request.TestContext(t)
	idp := newTestIdP(t)
	provider := &OpenIDProvider{}

	_, err := provider.GetSSOSettings(rctx, openIDConfig(idp, "client-id"), model.ServiceOpenid)
	require.NoError(t, err)
	assert.Equal(t, int64(1), idp.discoveryHits.Load(), "discovery should be fetched on first use")

	_, err = provider.GetSSOSettings(rctx, openIDConfig(idp, "client-id"), model.ServiceOpenid)
	require.NoError(t, err)
	assert.Equal(t, int64(1), idp.discoveryHits.Load(), "discovery should be cached")

	_, err = provider.GetSSOSettings(rctx, openIDConfig(idp, "different-client-id"), model.ServiceOpenid)
	require.NoError(t, err)
	assert.Equal(t, int64(2), idp.discoveryHits.Load(), "a changed client id should re-resolve")

	_, err = provider.GetSSOSettings(rctx, openIDConfig(idp, "client-id"), model.ServiceOpenid)
	require.NoError(t, err)
	assert.Equal(t, int64(2), idp.discoveryHits.Load(), "switching back should hit the cache, not the network")
}

// TestResolveIdPConcurrent exercises the fast path against a concurrent reconfiguration:
// the verifier and the cache key it belongs to must never be observed out of sync.
func TestResolveIdPConcurrent(t *testing.T) {
	rctx := request.TestContext(t)
	first := newTestIdP(t)
	second := newTestIdP(t)
	provider := &OpenIDProvider{}

	configs := []*model.Config{openIDConfig(first, "client-a"), openIDConfig(second, "client-b")}
	tokens := []string{first.idToken(t, "client-a", "user-a"), second.idToken(t, "client-b", "user-b")}

	var wg sync.WaitGroup
	for i := range configs {
		for range 25 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				settings, err := provider.GetSSOSettings(rctx, configs[i], model.ServiceOpenid)
				if assert.NoError(t, err) {
					assert.NotEmpty(t, *settings.TokenEndpoint)
				}
				// The token may be verified against whichever IdP another goroutine
				// resolved last, but a successful verification must never return a
				// subject the corresponding IdP did not sign for.
				if user, err := provider.GetUserFromIdToken(rctx, tokens[i]); err == nil {
					require.NotNil(t, user)
					assert.Equal(t, []string{"user-a", "user-b"}[i], *user.AuthData)
				}
			}()
		}
	}
	wg.Wait()
}

func TestIsSameUser(t *testing.T) {
	rctx := request.TestContext(t)
	provider := &OpenIDProvider{}

	auth1 := "abc"
	auth2 := "xyz"

	t.Run("same auth data", func(t *testing.T) {
		assert.True(t, provider.IsSameUser(rctx, &model.User{AuthData: &auth1}, &model.User{AuthData: &auth1}))
	})
	t.Run("different auth data", func(t *testing.T) {
		assert.False(t, provider.IsSameUser(rctx, &model.User{AuthData: &auth1}, &model.User{AuthData: &auth2}))
	})
	t.Run("nil auth data", func(t *testing.T) {
		assert.False(t, provider.IsSameUser(rctx, &model.User{AuthData: nil}, &model.User{AuthData: &auth1}))
		assert.False(t, provider.IsSameUser(rctx, &model.User{AuthData: &auth1}, &model.User{AuthData: nil}))
	})
}
