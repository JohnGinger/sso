package proxy

import (
	"net/http"

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

func signWithJWT(req *http.Request) error {
	options := NewOptions()

	claims := jwtSignedClaims{
		User:   req.Header.Get("X-Forwarded-User"),
		Email:  req.Header.Get("X-Forwarded-Email"),
		Groups: req.Header.Get("X-Forwarded-Groups"),

		StandardClaims: jwt.StandardClaims{
			Issuer: "sso-proxy",
		},
	}

	if options.JwtHS256 != "" {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ss, err := token.SignedString(options.JwtHS256)
		if err != nil {
			return err
		}
		req.Header.Set("jwt-hs256", ss)
	}

	if options.JwtRS256PrivateKey != "" {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		ss, err := token.SignedString(options.JwtRS256PrivateKey)
		if err != nil {
			return err
		}
		req.Header.Set("jwt-rs256", ss)

	}
	return nil

}
