package proxy

import (
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func needsJWT() bool {
	options := NewOptions()

	return options.JwtHS256 != "" || options.JwtRS256PrivateKey != ""
}

type jwtSignedClaims struct {
	User   string `json:"X-Forwarded-User"`
	Email  string `json:"X-Forwarded-Email"`
	Groups string `json:"X-Forwarded-Groups"`
	jwt.StandardClaims
}

func getClaims(header http.Header, now time.Time) jwtSignedClaims {

	return jwtSignedClaims{
		User:   header.Get("X-Forwarded-User"),
		Email:  header.Get("X-Forwarded-Email"),
		Groups: header.Get("X-Forwarded-Groups"),
		StandardClaims: jwt.StandardClaims{
			Issuer:   "sso-proxy",
			IssuedAt: now.Unix(),
		},
	}
}

func signWithJWTSharedSecret(req *http.Request, sharedSecret string, now time.Time) error {
	logger := log.NewLogEntry()

	claims := getClaims(req.Header, now)

	logger.Info("Trying to sign shared secret")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(sharedSecret))
	if err != nil {
		return err
	}
	req.Header.Set("x-auth-jwt-hs256", ss)
	logger.Info("Signed string is", ss)
	return nil

}

func signWithJWTPrivateKey(req *http.Request, privateKey string, now time.Time) error {
	logger := log.NewLogEntry()
	logger.Info("Trying to sign private key ")

	claims := getClaims(req.Header, now)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		return err
	}

	ss, err := token.SignedString(key)
	if err != nil {
		return err
	}
	req.Header.Set("x-auth-jwt-rs256", ss)
	return nil
}

func setJWTHS25Signer(JwtHS256 string, now func() time.Time) func(*OAuthProxy) error {
	logger := log.NewLogEntry()
	return func(op *OAuthProxy) error {

		logger.Info("adding JWT HS256")

		op.jwtHS256Signer = func(req *http.Request) error {
			return signWithJWTSharedSecret(req, JwtHS256, now())
		}

		return nil
	}
}

func setJwtRS256Signer(JwtRS256PrivateKey string, now func() time.Time) func(*OAuthProxy) error {
	logger := log.NewLogEntry()
	return func(op *OAuthProxy) error {

		logger.Info("adding JWT RS256")

		op.jwtRS256PrivateKeySigner = func(req *http.Request) error {
			return signWithJWTPrivateKey(req, JwtRS256PrivateKey, now())
		}

		return nil
	}
}
