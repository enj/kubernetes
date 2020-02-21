/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dynamiccertificates

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	authenticationv1alpha1 "k8s.io/api/authentication/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationinformerv1alpha1 "k8s.io/client-go/informers/authentication/v1alpha1"
	authenticationlisterv1alpha1 "k8s.io/client-go/listers/authentication/v1alpha1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

var _ Notifier = &DynamicAuthenticationConfigCA{}
var _ CAContentProvider = &DynamicAuthenticationConfigCA{}
var _ ControllerRunner = &DynamicAuthenticationConfigCA{}

type starter interface {
	Start(stopCh <-chan struct{})
}

// TODO implicitAuds is unused but wired here in case we ever need it
func NewDynamicAuthenticationConfigCA(implicitAuds authenticator.Audiences, authConfigInformer authenticationinformerv1alpha1.AuthenticationConfigInformer, starter starter) *DynamicAuthenticationConfigCA {
	dynamicAuth := &DynamicAuthenticationConfigCA{
		caBundle:         &atomic.Value{},
		authConfigLister: authConfigInformer.Lister(),
		starter:          starter,
		listenersLock:    &sync.RWMutex{},
	}

	// start with a no-op CA bundle
	dynamicAuth.caBundle.Store(emptyCABundle)

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

var emptyCABundle = &nameCABundleAndVerifier{
	name: "auth-config-ca-bundles-empty",
}

type DynamicAuthenticationConfigCA struct {
	// the current CA bundle based on overall config
	caBundle *atomic.Value

	// dynamic config sources
	authConfigLister authenticationlisterv1alpha1.AuthenticationConfigLister

	// starts the informers we use
	starter starter

	// TODO do we need this lock?
	listenersLock *sync.RWMutex
	listeners     []Listener
}

type nameCABundleAndVerifier struct {
	name string
	data caBundleAndVerifier
}

func (d *DynamicAuthenticationConfigCA) Name() string {
	return d.caBundle.Load().(*nameCABundleAndVerifier).name
}

func (d *DynamicAuthenticationConfigCA) CurrentCABundleContent() []byte {
	return d.caBundle.Load().(*nameCABundleAndVerifier).data.caBundle
}

func (d *DynamicAuthenticationConfigCA) VerifyOptions() (x509.VerifyOptions, bool) {
	caBundle := d.caBundle.Load().(*nameCABundleAndVerifier).data
	return caBundle.verifyOptions, len(caBundle.caBundle) > 0
}

func (d *DynamicAuthenticationConfigCA) AddListener(listener Listener) {
	d.listenersLock.Lock()
	d.listeners = append(d.listeners, listener)
	d.listenersLock.Unlock()
}

func (d *DynamicAuthenticationConfigCA) RunOnce() error {
	d.updateConfiguration() // TODO not sure if there is any point in running this function here
	return nil
}

func (d *DynamicAuthenticationConfigCA) Run(_ int, stopCh <-chan struct{}) {
	d.starter.Start(stopCh)
	<-stopCh
}

func (d *DynamicAuthenticationConfigCA) updateConfiguration() {
	authenticationConfigs, err := d.authConfigLister.List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error updating dynamic authentication configuration: %w", err))
		return
	}

	caBundle := authConfigsToCA(authenticationConfigs)
	if bytes.Equal(d.CurrentCABundleContent(), caBundle.data.caBundle) {
		return
	}

	d.caBundle.Store(caBundle)

	d.listenersLock.RLock()
	for _, listener := range d.listeners {
		listener.Enqueue()
	}
	d.listenersLock.RUnlock()
}

// TODO unit tests
func authConfigsToCA(authenticationConfigs []*authenticationv1alpha1.AuthenticationConfig) *nameCABundleAndVerifier {
	var (
		caBundles [][]byte
		names     []string
	)

	for _, authenticationConfig := range authenticationConfigs {
		spec := authenticationConfig.Spec
		switch spec.Type {
		case authenticationv1alpha1.AuthenticationConfigTypeX509:
			x509Config := spec.X509
			if x509Config == nil {
				continue // TODO drop when validation makes this impossible
			}

			// TODO drop when validation/REST storage makes this impossible
			caBundle := bytes.TrimSpace(x509Config.CABundle)
			if len(caBundle) == 0 {
				continue
			}

			// TODO drop when validation makes this impossible
			if _, err := newCABundleAndVerifier(authenticationConfig.Name, caBundle); err != nil {
				klog.V(2).Infof("CA authentication config %s has invalid content: %v", authenticationConfig.Name, err)
				continue
			}

			caBundles = append(caBundles, caBundle)
			names = append(names, authenticationConfig.Name)

		case authenticationv1alpha1.AuthenticationConfigTypeOIDC, authenticationv1alpha1.AuthenticationConfigTypeWebhook:
			// safe to ignore
			continue

		default:
			klog.Errorf("authentication config %s has unknown type %s", authenticationConfig.Name, authenticationConfig.Spec.Type)
			continue
		}
	}

	if len(caBundles) == 0 {
		return emptyCABundle
	}

	name := fmt.Sprintf("auth-config-ca-bundles:(%s)", strings.Join(names, ","))
	caBundle, err := newCABundleAndVerifier(name, bytes.Join(caBundles, []byte("\n")))
	if err != nil {
		// because we're made up of already vetted values, this indicates some kind of coding error
		panic(err)
	}

	return &nameCABundleAndVerifier{name: name, data: *caBundle}
}
