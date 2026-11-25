package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// EncryptAESGCM encrypts plaintext using a 32-byte AES-256-GCM key.
func EncryptAESGCM(key []byte, plaintext string) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// DecryptAESGCM decrypts AES-256-GCM ciphertext.
func DecryptAESGCM(key []byte, ciphertext []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// HashPassword hashes a password with a random 16-byte salt and iterated HMAC-SHA256.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived := stretchKey([]byte(password), salt, 50000)
	return fmt.Sprintf("v1$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(derived)), nil
}

// VerifyPassword checks a plaintext password against a stored v1$salt$hash string.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	actual := stretchKey([]byte(password), salt, 50000)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func stretchKey(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	sum := mac.Sum(nil)
	for i := 1; i < iterations; i++ {
		mac.Reset()
		mac.Write(sum)
		sum = mac.Sum(nil)
	}
	return sum
}

// TokenClaims represents authenticated user session claims.
type TokenClaims struct {
	UserID   string `json:"uid"`
	TenantID string `json:"tid"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
}

// SignToken creates a compact HMAC-SHA256 signed token.
func SignToken(secret []byte, claims TokenClaims) (string, error) {
	if len(secret) < 16 {
		return "", errors.New("jwt secret too short")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	sig := SignHMAC(secret, []byte(signingInput))
	return signingInput + "." + sig, nil
}

// VerifyToken validates signature and expiration and returns TokenClaims.
func VerifyToken(secret []byte, token string) (TokenClaims, error) {
	var claims TokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, errors.New("malformed token")
	}
	signingInput := parts[0] + "." + parts[1]
	expectedSig := SignHMAC(secret, []byte(signingInput))
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
		return claims, errors.New("invalid token signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, err
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return claims, err
	}
	if time.Now().Unix() > claims.Exp {
		return claims, errors.New("token expired")
	}
	return claims, nil
}

// SignHMAC returns a base64url-encoded HMAC-SHA256 signature.
func SignHMAC(secret, data []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// RandomHex returns n random bytes encoded as hex.
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
