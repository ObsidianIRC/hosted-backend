package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OAuth2 token-endpoint proxy. GitHub (and a few other IdPs) refuse to
// send CORS headers on /login/oauth/access_token, so a browser SPA can't
// POST directly. The SPA hits POST /oauth/exchange/{provider} on this
// backend instead; we relay the form body upstream with the same shape
// the IdP expects, attach an Accept: application/json so we get JSON
// back, and return the upstream response as-is.
//
// Allowed providers + their upstream URLs come from env, so this is not
// an open SSRF -- only the URLs the operator configured can be reached.
//
//	OAUTH_PROXY_GITHUB=https://github.com/login/oauth/access_token
//	OAUTH_PROXY_GOOGLE=https://oauth2.googleapis.com/token   (etc.)
//
// Optional: OAUTH_PROXY_<PROVIDER>_CLIENT_SECRET -- if set, attached to
// the upstream POST so OAuth Apps that require a secret (rather than
// PKCE-only GitHub Apps) work without leaking the secret to the SPA.
func handleOAuthExchange(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// /oauth/exchange/{provider}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/oauth/exchange/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing provider", http.StatusBadRequest)
		return
	}
	provider := strings.ToUpper(parts[0])
	upstream := os.Getenv("OAUTH_PROXY_" + provider)
	if upstream == "" {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
		return
	}
	form := r.PostForm
	if secret := os.Getenv("OAUTH_PROXY_" + provider + "_CLIENT_SECRET"); secret != "" {
		form.Set("client_secret", secret)
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream,
		strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "build upstream req: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "obsidianirc-oauth-proxy")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "upstream request: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		http.Error(w, "read upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(body); err != nil {
		fmt.Fprintf(os.Stderr, "oauth-exchange: write back: %v\n", err)
	}
}
