package proxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/hostmux"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
)

type SSOProxy struct {
	http.Handler
}

func New(opts *Options) (*SSOProxy, error) {
	optFuncs := []func(*OAuthProxy) error{}

	var requestSigner *RequestSigner
	var err error

	if opts.RequestSigningKey != "" {
		requestSigner, err = NewRequestSigner(opts.RequestSigningKey)
		if err != nil {
			return nil, err
		}
		optFuncs = append(optFuncs, SetRequestSigner(requestSigner))
	}

	logger := log.NewLogEntry()

	if opts.JwtHS256 != "" {
		logger.Info(fmt.Sprintf("Should add JWT shared key in proxy"))
		optFuncs = append(optFuncs, setJWTHS25Signer(opts.JwtHS256, func() time.Time { return time.Now() }))
	}

	if opts.JwtRS256PrivateKey != "" {
		logger.Info(fmt.Sprintf("Should add JWT public key in proxy"))
		optFuncs = append(optFuncs, setJwtRS256Signer(opts.JwtRS256PrivateKey, func() time.Time { return time.Now() }))
	}

	hostRouter := hostmux.NewRouter()
	for _, upstreamConfig := range opts.upstreamConfigs {
		provider, err := newProvider(opts, upstreamConfig)
		if err != nil {
			return nil, err
		}

		handler, err := NewUpstreamReverseProxy(upstreamConfig, requestSigner)
		if err != nil {
			return nil, err
		}

		validators := []options.Validator{}
		if len(upstreamConfig.AllowedEmailAddresses) != 0 {
			validators = append(validators, options.NewEmailAddressValidator(upstreamConfig.AllowedEmailAddresses))
		}

		if len(upstreamConfig.AllowedEmailDomains) != 0 {
			validators = append(validators, options.NewEmailDomainValidator(upstreamConfig.AllowedEmailDomains))
		}

		validators = append(validators, options.NewEmailGroupValidator(provider, upstreamConfig.AllowedGroups))

		optFuncs = append(optFuncs,
			SetProvider(provider),
			SetCookieStore(opts),
			SetUpstreamConfig(upstreamConfig),
			SetProxyHandler(handler),
			SetValidators(validators),
		)

		oauthproxy, err := NewOAuthProxy(opts, optFuncs...)
		if err != nil {
			return nil, err
		}

		switch route := upstreamConfig.Route.(type) {
		case *SimpleRoute:
			hostRouter.HandleStatic(route.FromURL.Host, oauthproxy.Handler())
		case *RewriteRoute:
			hostRouter.HandleRegexp(route.FromRegex, oauthproxy.Handler())
		default:
			return nil, fmt.Errorf("unknown route type")
		}
	}

	healthcheckHandler := setHealthCheck("/ping", hostRouter)

	return &SSOProxy{
		healthcheckHandler,
	}, nil
}
