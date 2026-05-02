package main

import (
	"net/http"
	"os"
)

// JWTClaims is the legacy claims shape used by handlers that pre-date
// the move to draft/authtoken.  It is now populated from TOKEN
// VALIDATE results (see tokenauth.go) so existing handlers keep
// working without changes.  New code should prefer
// TokenClaimsFromCtx().
type JWTClaims struct {
	Exp     int64    `json:"exp"`
	Iss     string   `json:"iss"`
	Sub     string   `json:"sub"`
	Account string   `json:"account"`
	Umodes  []string `json:"umodes"`
	Cmodes  []string `json:"cmodes"`
}

// AuthMiddleware validates the request's bearer token via the IRC
// server's draft/authtoken `TOKEN VALIDATE` flow and, if successful,
// injects a legacy JWTClaims into the request context as `jwt_claims`.
//
// This is a thin wrapper around TokenAuthMiddleware; it exists so the
// existing call sites in main.go continue to compile unchanged.
func AuthMiddleware(next http.HandlerFunc, requireIRCOp bool) http.HandlerFunc {
	return TokenAuthMiddleware(next, requireIRCOp)
}

// ServerAuthMiddleware verifies the X-ObsidianIRC-Key header that
// IRCds use to call backend endpoints (server-to-backend trust).
// Unrelated to user auth so it stays untouched by the authtoken
// migration.
func ServerAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-ObsidianIRC-Key")
		expectedKey := os.Getenv("IRC_SERVER_KEY")
		if expectedKey == "" {
			http.Error(w, "IRC server key not configured", http.StatusInternalServerError)
			return
		}

		if key != expectedKey {
			http.Error(w, "Invalid IRC server key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
