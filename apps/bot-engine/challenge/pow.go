package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Manager issues and verifies self-contained Proof-of-Work challenges and signed clearance cookies.
type Manager struct {
	Secret     []byte
	Difficulty int // leading zero hex nibbles required (e.g. 3 => "000...")
	TTL        time.Duration
}

func NewManager(secret []byte, difficulty int, ttl time.Duration) *Manager {
	if difficulty < 1 || difficulty > 6 {
		difficulty = 3
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Manager{Secret: secret, Difficulty: difficulty, TTL: ttl}
}

// CreateChallenge generates a stateless PoW nonce bound to clientPrefix and userAgent.
func (m *Manager) CreateChallenge(clientPrefix, userAgent string, now time.Time) string {
	exp := now.Add(5 * time.Minute).Unix()
	payload := fmt.Sprintf("%d|%s|%s", exp, clientPrefix, hashShort(userAgent))
	sig := m.sign(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// VerifyPoW verifies the challenge token and proof-of-work solution, returning a signed clearance cookie value.
func (m *Manager) VerifyPoW(token, solution, clientPrefix, userAgent string, now time.Time) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", false
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	payload := string(rawPayload)
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(m.sign(payload))) != 1 {
		return "", false
	}
	fields := strings.Split(payload, "|")
	if len(fields) != 3 {
		return "", false
	}
	exp, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || now.Unix() > exp {
		return "", false
	}
	if fields[1] != clientPrefix || fields[2] != hashShort(userAgent) {
		return "", false
	}

	sum := sha256.Sum256([]byte(token + ":" + solution))
	hexSum := hex.EncodeToString(sum[:])
	if !strings.HasPrefix(hexSum, strings.Repeat("0", m.Difficulty)) {
		return "", false
	}

	cookieExp := now.Add(m.TTL).Unix()
	cookiePayload := fmt.Sprintf("%d|%s|%s", cookieExp, clientPrefix, hashShort(userAgent))
	cookie := base64.RawURLEncoding.EncodeToString([]byte(cookiePayload)) + "." + m.sign(cookiePayload)
	return cookie, true
}

// VerifyClearance validates an existing clearance cookie against clientPrefix and userAgent.
func (m *Manager) VerifyClearance(cookie, clientPrefix, userAgent string, now time.Time) bool {
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 {
		return false
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload := string(rawPayload)
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(m.sign(payload))) != 1 {
		return false
	}
	fields := strings.Split(payload, "|")
	if len(fields) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || now.Unix() > exp {
		return false
	}
	return fields[1] == clientPrefix && fields[2] == hashShort(userAgent)
}

func (m *Manager) sign(data string) string {
	mac := hmac.New(sha256.New, m.Secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hashShort(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}
