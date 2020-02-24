package dynamic

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync/atomic"
	"time"

	authenticationv1alpha1 "k8s.io/api/authentication/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/apiserver/pkg/authentication/request/websocket"
	"k8s.io/apiserver/pkg/authentication/request/x509"
	tokencache "k8s.io/apiserver/pkg/authentication/token/cache"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	authenticationinformerv1alpha1 "k8s.io/client-go/informers/authentication/v1alpha1"
	authenticationlisterv1alpha1 "k8s.io/client-go/listers/authentication/v1alpha1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog"
)

func New(implicitAuds authenticator.Audiences, authConfigInformer authenticationinformerv1alpha1.AuthenticationConfigInformer, noTokenAuth bool) authenticator.Request {
	dynamicAuth := &dynamicAuthConfig{
		delegate:         &atomic.Value{},
		implicitAuds:     implicitAuds,
		authConfigLister: authConfigInformer.Lister(),
		noTokenAuth:      noTokenAuth,
	}

	// start with a no-op authenticator
	dynamicAuth.delegate.Store(box{emptyAuthenticator})

	// rebuild the entire config on any change since this is a slow moving API
	// authentication fails closed, so we do not need to sync the informer
	// using the informer here guarantees that the informer factory does lazy loading for this type
	authConfigInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ interface{}) { dynamicAuth.updateConfiguration() },
		UpdateFunc: func(_, _ interface{}) { dynamicAuth.updateConfiguration() },
		DeleteFunc: func(_ interface{}) { dynamicAuth.updateConfiguration() },
	})

	return dynamicAuth
}

var emptyAuthenticator authenticator.Request = authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
	return nil, false, nil
})

// atomic.Value requires a consistent concrete type with calls to Store
type box struct {
	authenticator.Request
}

type dynamicAuthConfig struct {
	// the current authenticator based on overall config
	delegate *atomic.Value

	// static config
	implicitAuds authenticator.Audiences

	// dynamic config sources
	authConfigLister authenticationlisterv1alpha1.AuthenticationConfigLister

	// if noTokenAuth is true, token based authentication methods are ignored
	noTokenAuth bool
}

func (d *dynamicAuthConfig) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return d.delegate.Load().(authenticator.Request).AuthenticateRequest(req)
}

func (d *dynamicAuthConfig) updateConfiguration() {
	authenticationConfigs, err := d.authConfigLister.List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error updating dynamic authentication configuration: %w", err))
		return
	}
	d.delegate.Store(box{authConfigsToAuthenticator(d.implicitAuds, authenticationConfigs, d.noTokenAuth)})
}

// TODO unit tests
func authConfigsToAuthenticator(implicitAuds authenticator.Audiences, authenticationConfigs []*authenticationv1alpha1.AuthenticationConfig, noTokenAuth bool) authenticator.Request {
	authenticators := make([]authenticator.Request, 0, len(authenticationConfigs))

	for _, authenticationConfig := range authenticationConfigs {
		spec := authenticationConfig.Spec
		switch spec.Type {
		case authenticationv1alpha1.AuthenticationConfigTypeX509:
			x509Config := spec.X509
			if x509Config == nil {
				continue // TODO drop when validation makes this impossible
			}
			var err error
			opts := x509.DefaultVerifyOptions()
			opts.Roots, err = cert.NewPoolFromBytes(x509Config.CABundle)
			if err != nil {
				continue // TODO use validation to make impossible
			}
			certAuth := x509.New(opts, x509.CommonNameUserConversion)
			authenticators = append(authenticators, certAuth)

		case authenticationv1alpha1.AuthenticationConfigTypeOIDC:
			if noTokenAuth {
				continue
			}

			oidcConfig := spec.OIDC
			if oidcConfig == nil {
				continue // TODO drop when validation makes this impossible
			}
			oidcAuth, err := oidcConfigToAuthenticator(implicitAuds, oidcConfig)
			if err != nil {
				// TODO update status?
				utilruntime.HandleError(fmt.Errorf("failed to honor OIDC config %s: %w", authenticationConfig.Name, err))
				continue
			}
			authenticators = append(authenticators, oidcAuth)

		case authenticationv1alpha1.AuthenticationConfigTypeWebhook:
			if noTokenAuth {
				continue
			}

			// TODO implement

		default:
			klog.Errorf("authentication config %s has unknown type %s", authenticationConfig.Name, authenticationConfig.Spec.Type)
			continue
		}
	}

	if len(authenticators) == 0 {
		return emptyAuthenticator
	}

	// guarantee no particular ordering for now
	// TODO think about this more
	rand.Shuffle(len(authenticators), func(i, j int) {
		authenticators[i], authenticators[j] = authenticators[j], authenticators[i]
	})

	return union.New(authenticators...)
}

func oidcConfigToAuthenticator(implicitAuds authenticator.Audiences, oidcConfig *authenticationv1alpha1.OIDCConfig) (authenticator.Request, error) {
	// TODO turn newAuthenticatorFromOIDCIssuerURL's logic into proper defaulting and validation
	oidcAuth, err := oidc.New(oidc.Options{
		IssuerURL:     oidcConfig.Issuer,
		ClientID:      oidcConfig.ClientID,
		UsernameClaim: oidcConfig.UsernameClaim,
		APIAudiences:  implicitAuds,

		// TODO wire these as well
		CAFile:               "",
		UsernamePrefix:       "",
		GroupsClaim:          "",
		GroupsPrefix:         "",
		SupportedSigningAlgs: nil,
		RequiredClaims:       nil,
	})
	if err != nil {
		return nil, err
	}

	// TODO this layering is pretty expensive in comparison to the built in auth stack
	tokenAuth := tokencache.New(oidcAuth, false, 30*time.Second, 10*time.Second)
	return union.New(bearertoken.New(tokenAuth), websocket.NewProtocolAuthenticator(tokenAuth)), nil
}
