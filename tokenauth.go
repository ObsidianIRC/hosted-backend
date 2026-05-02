// Token-based authentication using the IRCv3 draft/authtoken
// `TOKEN VALIDATE` flow.
//
// The backend opens a long-lived plaintext IRC connection to the
// configured ObbyIRCd, registers as a service-style client, then for
// every request that needs auth issues a `TOKEN VALIDATE` and reads
// back the claim batch synchronously.  Validate replies are
// distinguished by a per-call random batch reference.
//
// Required environment variables:
//
//	IRC_HOST         host:port of the IRC server (default 127.0.0.1:6667)
//	IRC_TLS          set to "1" to wrap the connection in TLS
//	IRC_NICK         nick the backend uses (default obbyirc-backend)
//	IRC_USER         user/realname (default backend)
//	IRC_PASS         optional PASS line value
//	IRC_SERVICE      service key the tokens were minted for
//	                 (default FILEHOST -- adjust to whatever your
//	                 obbyircd authtoken { service ... } block uses)
//	IRC_SERVICE_URL  url that matches the service block (must equal
//	                 the URL the IRCd has on file or VALIDATE returns
//	                 INVALID_TOKEN)
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenClaims is the subset of draft/authtoken claims our middleware
// needs to authorise requests.  Extra TOKEN CLAIM keys returned by
// the IRCd are kept in Extra so future endpoints can pick them up
// without a middleware change.
type TokenClaims struct {
	Account    string            // CLAIM account
	Name       string            // CLAIM name (current nick)
	Scope      string            // CLAIM scope
	MemberOf   []string          // CLAIM member_of
	OperatorOf []string          // CLAIM operator_of
	Extra      map[string]string // any other CLAIM key=value
}

// IsOperator reports whether the token's operator_of list contains the
// network's all-opers channel.  We treat membership in the configured
// "oper channel" (default "#opers") as the proxy for IRC-operator
// status because the spec doesn't define an explicit oper claim.
//
// Operators that prefer a different signal can override OPER_CHANNEL.
func (c *TokenClaims) IsOperator() bool {
	want := os.Getenv("OPER_CHANNEL")
	if want == "" {
		want = "#opers"
	}
	for _, ch := range c.OperatorOf {
		if strings.EqualFold(ch, want) {
			return true
		}
	}
	for _, ch := range c.MemberOf {
		if strings.EqualFold(ch, want) {
			return true
		}
	}
	return false
}

// tokenClient is a serialised wrapper around a single IRC connection
// that issues TOKEN VALIDATE requests.  Concurrent callers are
// queued behind a mutex so request/response correlation stays simple
// (one inflight VALIDATE at a time).
type tokenClient struct {
	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
	service string
	url     string
}

var (
	tokClient     *tokenClient
	tokClientOnce sync.Once
)

func getTokenClient() (*tokenClient, error) {
	var initErr error
	tokClientOnce.Do(func() {
		c := &tokenClient{
			service: getenv("IRC_SERVICE", "FILEHOST"),
			url:     os.Getenv("IRC_SERVICE_URL"),
		}
		if c.url == "" {
			initErr = errors.New("IRC_SERVICE_URL is required")
			return
		}
		if err := c.dial(); err != nil {
			initErr = err
			return
		}
		tokClient = c
	})
	if initErr != nil {
		return nil, initErr
	}
	if tokClient == nil {
		return nil, errors.New("token client not initialised")
	}
	return tokClient, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (c *tokenClient) dial() error {
	host := getenv("IRC_HOST", "127.0.0.1:6667")
	useTLS := os.Getenv("IRC_TLS") == "1"

	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.Dial("tcp", host, &tls.Config{
			InsecureSkipVerify: os.Getenv("IRC_TLS_INSECURE") == "1",
		})
	} else {
		conn, err = net.DialTimeout("tcp", host, 10*time.Second)
	}
	if err != nil {
		return fmt.Errorf("dial irc %s: %w", host, err)
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)

	nick := getenv("IRC_NICK", "obbyirc-backend")
	user := getenv("IRC_USER", "backend")
	pass := os.Getenv("IRC_PASS")

	// Bare-bones registration.  We negotiate `batch` so we can
	// receive batched VALIDATE replies, plus `draft/authtoken` so the
	// server lets us send batched requests.
	c.write("CAP LS 302")
	if pass != "" {
		c.write("PASS " + pass)
	}
	c.write("NICK " + nick)
	c.write("USER " + user + " 0 * :" + user)
	c.write("CAP REQ :batch draft/authtoken")
	c.write("CAP END")

	// Drain until 001 (welcome) so we know registration completed.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		line, err := c.readLine(15 * time.Second)
		if err != nil {
			return fmt.Errorf("registration read: %w", err)
		}
		// 001 = RPL_WELCOME
		if isNumeric(line, "001") {
			return nil
		}
		// PING during registration
		if strings.HasPrefix(line, "PING ") {
			c.write("PONG " + strings.TrimPrefix(line, "PING "))
		}
	}
	return errors.New("did not receive RPL_WELCOME within 15s")
}

func (c *tokenClient) write(line string) error {
	_, err := c.conn.Write([]byte(line + "\r\n"))
	return err
}

func (c *tokenClient) readLine(timeout time.Duration) (string, error) {
	if timeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	}
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func isNumeric(line, num string) bool {
	parts := strings.SplitN(line, " ", 3)
	return len(parts) >= 2 && parts[1] == num
}

// validate runs a single TOKEN VALIDATE round-trip and returns the
// claims.  Concurrent callers are serialised because we share one
// connection and don't want batch refs to interleave.
func (c *tokenClient) validate(ctx context.Context, token string) (*TokenClaims, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Best-effort reconnect if the link died.
	if c.conn == nil {
		if err := c.dial(); err != nil {
			return nil, err
		}
	}

	// Fire the validate.  Tokens up to ~200 bytes fit in one line; for
	// anything longer we'd switch to the client-initiated draft/
	// authtoken batch form.  Our generated tokens are 32-char alnum
	// so single-line is fine.
	cmd := fmt.Sprintf("TOKEN VALIDATE %s %s :%s", c.service, c.url, token)
	if err := c.write(cmd); err != nil {
		// Reset and retry once on broken pipe.
		_ = c.conn.Close()
		c.conn = nil
		if err := c.dial(); err != nil {
			return nil, err
		}
		if err := c.write(cmd); err != nil {
			return nil, err
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	var (
		batchRef     string
		insideBatch  bool
		claims       = &TokenClaims{Extra: map[string]string{}}
		concatBuffer = map[string]*strings.Builder{}
	)

	for time.Now().Before(deadline) {
		line, err := c.readLine(time.Until(deadline))
		if err != nil {
			return nil, fmt.Errorf("read validate reply: %w", err)
		}

		// PING handling so the connection stays alive.
		if strings.HasPrefix(line, "PING ") {
			c.write("PONG " + strings.TrimPrefix(line, "PING "))
			continue
		}

		// FAIL TOKEN <code> ... -- abort.
		if idx := strings.Index(line, " FAIL TOKEN "); idx >= 0 {
			rest := strings.TrimSpace(line[idx+len(" FAIL TOKEN "):])
			parts := strings.SplitN(rest, " ", 2)
			return nil, fmt.Errorf("token validation failed: %s", parts[0])
		}

		tags, source, cmd, params, trailing := parseIRCLine(line)
		_ = source

		// Track the batch we care about.
		if cmd == "BATCH" && len(params) >= 1 {
			ref := params[0]
			if strings.HasPrefix(ref, "+") && len(params) >= 2 && params[1] == "draft/authtoken" {
				batchRef = ref[1:]
				insideBatch = true
				continue
			}
			if strings.HasPrefix(ref, "-") && ref[1:] == batchRef {
				return claims, nil
			}
			continue
		}

		if !insideBatch {
			continue
		}

		// Make sure this line is part of OUR batch.
		if !taggedFromBatch(tags, batchRef) {
			continue
		}

		if cmd == "TOKEN" && len(params) >= 2 && params[0] == "CLAIM" {
			key := params[1]
			val := trailing
			// Per spec, claim values may be split across multiple
			// lines.  Concatenate all values for the same key.
			if b, ok := concatBuffer[key]; ok {
				b.WriteString(val)
				val = b.String()
			} else {
				b := &strings.Builder{}
				b.WriteString(val)
				concatBuffer[key] = b
				val = b.String()
			}
			switch key {
			case "account":
				claims.Account = val
			case "name":
				claims.Name = val
			case "scope":
				claims.Scope = val
			case "member_of":
				claims.MemberOf = strings.Fields(val)
			case "operator_of":
				claims.OperatorOf = strings.Fields(val)
			default:
				claims.Extra[key] = val
			}
		}
	}
	return nil, errors.New("validate reply timed out")
}

// taggedFromBatch returns true if the message-tag block contains
// `batch=<ref>` for the given ref.
func taggedFromBatch(tags, ref string) bool {
	if tags == "" || ref == "" {
		return false
	}
	for _, t := range strings.Split(tags, ";") {
		if t == "batch="+ref {
			return true
		}
	}
	return false
}

// parseIRCLine is a permissive parser that returns
// (tags, source, command, params[], trailing).  Tags includes the `@`.
// trailing is the text after `:` on the wire (already stripped).
func parseIRCLine(line string) (tags, source, command string, params []string, trailing string) {
	rest := line
	if strings.HasPrefix(rest, "@") {
		idx := strings.IndexByte(rest, ' ')
		if idx < 0 {
			return rest, "", "", nil, ""
		}
		tags = rest[1:idx]
		rest = rest[idx+1:]
	}
	if strings.HasPrefix(rest, ":") {
		idx := strings.IndexByte(rest, ' ')
		if idx < 0 {
			return tags, rest[1:], "", nil, ""
		}
		source = rest[1:idx]
		rest = rest[idx+1:]
	}
	if i := strings.Index(rest, " :"); i >= 0 {
		trailing = rest[i+2:]
		rest = rest[:i]
	}
	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return tags, source, "", nil, trailing
	}
	command = parts[0]
	params = parts[1:]
	return tags, source, command, params, trailing
}

// randomBatchRef -- not used (we let the IRCd choose), but kept for
// possible client-initiated batches in the future.
func randomBatchRef() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// TokenAuthMiddleware verifies a draft/authtoken bearer and, on
// success, injects the resulting claims (and a synthetic JWTClaims
// for backward compatibility with handlers that still read the old
// context value) into the request.
func TokenAuthMiddleware(next http.HandlerFunc, requireIRCOp bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader || token == "" {
			http.Error(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		client, err := getTokenClient()
		if err != nil {
			http.Error(w, "auth backend unavailable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		claims, err := client.validate(ctx, token)
		if err != nil {
			http.Error(w, "token validation failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if requireIRCOp && !claims.IsOperator() {
			http.Error(w, "IRCop status required", http.StatusForbidden)
			return
		}

		// Bridge to the legacy JWTClaims-shaped context value so
		// existing handlers that read `jwt_claims` keep working
		// without modification.  We keep the string key so callers
		// don't need to import a new constant.
		legacy := &JWTClaims{
			Sub:     claims.Name,
			Account: claims.Account,
		}
		if claims.IsOperator() {
			legacy.Umodes = []string{"o"}
		}
		ctx = context.WithValue(r.Context(), "jwt_claims", legacy)
		ctx = context.WithValue(ctx, ctxKeyTokenClaims, claims)
		next(w, r.WithContext(ctx))
	}
}

// Context key for the new TOKEN claims.  Unexported so handlers must
// go through TokenClaimsFromCtx.
type ctxKey int

const ctxKeyTokenClaims ctxKey = iota

// TokenClaimsFromCtx returns the validated TOKEN claims attached by
// TokenAuthMiddleware, or nil for unauthenticated requests.
func TokenClaimsFromCtx(r *http.Request) *TokenClaims {
	if v, ok := r.Context().Value(ctxKeyTokenClaims).(*TokenClaims); ok {
		return v
	}
	return nil
}
