package dynamic

import (
	"fmt"
	"net/http"
	"sync/atomic"

	authenticationv1alpha1 "k8s.io/api/authentication/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationinformerv1alpha1 "k8s.io/client-go/informers/authentication/v1alpha1"
	authenticationlisterv1alpha1 "k8s.io/client-go/listers/authentication/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

func New(implicitAuds authenticator.Audiences, authConfigInformer authenticationinformerv1alpha1.AuthenticationConfigInformer) (authenticator.Request, func(stopCh <-chan struct{})) {
	dynamicAuth := &dynamicAuthConfig{
		delegate:         &atomic.Value{},
		implicitAuds:     implicitAuds,
		authConfigLister: authConfigInformer.Lister(),
	}

	// start with a no-op authenticator
	dynamicAuth.delegate.Store(emptyAuthenticator)

	// rebuild the entire config on any change since this is a slow moving API
	// authentication fails closed, so we do not need to sync the informer
	// using the informer here guarantees that the informer factory does lazy loading for this type
	authConfigInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ interface{}) { dynamicAuth.updateConfiguration() },
		UpdateFunc: func(_, _ interface{}) { dynamicAuth.updateConfiguration() },
		DeleteFunc: func(_ interface{}) { dynamicAuth.updateConfiguration() },
	})

	return dynamicAuth, func(stopCh <-chan struct{}) {
		// TODO drop stopCh func
	}
}

var emptyAuthenticator authenticator.Request = authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
	return nil, false, nil
})

type dynamicAuthConfig struct {
	// the current authenticator based on overall config
	delegate *atomic.Value

	// static config
	implicitAuds authenticator.Audiences

	// dynamic config sources
	authConfigLister authenticationlisterv1alpha1.AuthenticationConfigLister
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
	d.delegate.Store(authConfigsToAuthenticator(d.implicitAuds, authenticationConfigs))
}

// TODO unit tests
func authConfigsToAuthenticator(implicitAuds authenticator.Audiences, authenticationConfigs []*authenticationv1alpha1.AuthenticationConfig) authenticator.Request {
	// TODO logic
	return emptyAuthenticator
}
