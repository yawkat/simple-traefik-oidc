package simple_traefik_oidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName      = "_oidc_session"
	callbackPath           = "/_oidc/callback"
	defaultSessionDuration = 20 * time.Hour
)

// Config holds the plugin configuration.
type Config struct {
	ProviderUrl        string   `json:"providerUrl"`
	ClientId           string   `json:"clientId"`
	ClientSecret       string   `json:"clientSecret"`
	SessionKey         string   `json:"sessionKey"`
	Host               string   `json:"host"`
	CookieSameSite     string   `json:"cookieSameSite"`
	SessionDurationMin int      `json:"sessionDurationMin"`
	ExcludedUrls       []string `json:"excludedUrls"`
}

func CreateConfig() *Config {
	return &Config{
		ProviderUrl:    "https://accounts.google.com",
		ClientId:       "YOUR_CLIENT_ID",
		ClientSecret:   "YOUR_CLIENT_SECRET",
		SessionKey:     "YOUR_SESSION_KEY",
		CookieSameSite: "lax",
		ExcludedUrls:   []string{},
	}
}

type oidcEndpoints struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type MyPlugin struct {
	next            http.Handler
	name            string
	config          *Config
	aesKey          []byte
	sameSite        http.SameSite
	sessionDuration time.Duration
	endpoints       *oidcEndpoints
	epOnce          sync.Once
	epErr           error
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	hash := sha256.Sum256([]byte(config.SessionKey))

	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(config.CookieSameSite) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "lax":
		sameSite = http.SameSiteLaxMode
	case "none":
		sameSite = http.SameSiteNoneMode
	case "":
		sameSite = http.SameSiteLaxMode
	default:
		return nil, fmt.Errorf("invalid cookieSameSite value: %q (must be strict, lax, or none)", config.CookieSameSite)
	}

	dur := defaultSessionDuration
	if config.SessionDurationMin > 0 {
		dur = time.Duration(config.SessionDurationMin) * time.Minute
	}

	return &MyPlugin{
		next:            next,
		name:            name,
		config:          config,
		aesKey:          hash[:],
		sameSite:        sameSite,
		sessionDuration: dur,
	}, nil
}

func (p *MyPlugin) encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	// produces nonce||ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (p *MyPlugin) decrypt(encoded string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

type sessionPayload struct {
	Type      string `json:"t"`
	ExpiresAt int64  `json:"exp"`
}

func (p *MyPlugin) createSessionCookie(r *http.Request) (*http.Cookie, error) {
	payload := sessionPayload{Type: "session", ExpiresAt: time.Now().Add(p.sessionDuration).Unix()}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	enc, err := p.encrypt(data)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    enc,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: p.sameSite,
		MaxAge:   int(p.sessionDuration.Seconds()),
	}, nil
}

func (p *MyPlugin) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	plaintext, err := p.decrypt(cookie.Value)
	if err != nil {
		return false
	}
	var payload sessionPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return false
	}
	return time.Now().Unix() < payload.ExpiresAt && payload.Type == "session"
}

func (p *MyPlugin) discoverEndpoints() (*oidcEndpoints, error) {
	p.epOnce.Do(func() {
		discoveryURL := strings.TrimRight(p.config.ProviderUrl, "/") + "/.well-known/openid-configuration"
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(discoveryURL)
		if err != nil {
			p.epErr = fmt.Errorf("oidc discovery failed: %w", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			p.epErr = fmt.Errorf("oidc discovery returned %d", resp.StatusCode)
			return
		}
		var ep oidcEndpoints
		if err := json.NewDecoder(resp.Body).Decode(&ep); err != nil {
			p.epErr = fmt.Errorf("oidc discovery decode failed: %w", err)
			return
		}
		p.endpoints = &ep
	})
	return p.endpoints, p.epErr
}

type statePayload struct {
	Type        string `json:"t"`
	RedirectURL string `json:"r"`
	ExpiresAt   int64  `json:"exp"`
}

func (p *MyPlugin) encryptState(redirectURL string) (string, error) {
	payload := statePayload{
		Type:        "state",
		RedirectURL: redirectURL,
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return p.encrypt(data)
}

func (p *MyPlugin) decryptState(state string) (string, error) {
	plaintext, err := p.decrypt(state)
	if err != nil {
		return "", err
	}
	var payload statePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return "", err
	}
	if time.Now().Unix() >= payload.ExpiresAt || payload.Type != "state" {
		return "", fmt.Errorf("state expired")
	}
	return payload.RedirectURL, nil
}

func requestURL(host string, r *http.Request) string {
	return "https://" + host + r.RequestURI
}

func callbackURL(host string) string {
	return "https://" + host + callbackPath
}

func (p *MyPlugin) isExcluded(reqURL string) bool {
	for _, exc := range p.config.ExcludedUrls {
		if reqURL == exc || strings.HasPrefix(reqURL, exc) {
			return true
		}
	}
	return false
}

func (p *MyPlugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == callbackPath {
		p.handleCallback(w, r)
		return
	}

	if p.isExcluded(requestURL(p.config.Host, r)) {
		p.next.ServeHTTP(w, r)
		return
	}

	if p.validSession(r) {
		p.next.ServeHTTP(w, r)
		return
	}

	p.startAuth(w, r)
}

func (p *MyPlugin) startAuth(w http.ResponseWriter, r *http.Request) {
	ep, err := p.discoverEndpoints()
	if err != nil {
		http.Error(w, "OIDC discovery error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	state, err := p.encryptState(requestURL(p.config.Host, r))
	if err != nil {
		http.Error(w, "Failed to create state", http.StatusInternalServerError)
		return
	}

	params := url.Values{
		"client_id":     {p.config.ClientId},
		"response_type": {"code"},
		"redirect_uri":  {callbackURL(p.config.Host)},
		"scope":         {"openid"},
		"state":         {state},
	}

	http.Redirect(w, r, ep.AuthorizationEndpoint+"?"+params.Encode(), http.StatusFound)
}

func (p *MyPlugin) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	redirectURL, err := p.decryptState(state)
	if err != nil {
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	ep, err := p.discoverEndpoints()
	if err != nil {
		http.Error(w, "OIDC discovery error", http.StatusInternalServerError)
		return
	}

	tokenResp, err := http.PostForm(ep.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL(p.config.Host)},
		"client_id":     {p.config.ClientId},
		"client_secret": {p.config.ClientSecret},
	})
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		http.Error(w, "Token exchange returned non-200", http.StatusInternalServerError)
		return
	}

	// Token content is irrelevant — a successful exchange proves authentication.
	cookie, err := p.createSessionCookie(r)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
