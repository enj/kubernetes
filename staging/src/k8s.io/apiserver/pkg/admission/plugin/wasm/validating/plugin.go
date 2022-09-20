/*
Copyright 2022 The Kubernetes Authors.

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

package validating

import (
	"context"
	"fmt"
	"io"
	"sync"

	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/initializer"
	wasmplugin "k8s.io/apiserver/pkg/admission/plugin/wasm/validating/plugin"
	webhookerrors "k8s.io/apiserver/pkg/admission/plugin/webhook/errors"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/generic"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/request"
	webhookrequest "k8s.io/apiserver/pkg/admission/plugin/webhook/request"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	quota "k8s.io/apiserver/pkg/quota/v1"
	webhookutil "k8s.io/apiserver/pkg/util/webhook"
	"k8s.io/apiserver/pkg/warning"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/component-base/featuregate"
	"k8s.io/klog/v2"
)

const PluginName = "ValidatingAdmissionWASM"

func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(configFile io.Reader) (admission.Interface, error) {
		plugin, err := NewValidatingAdmissionWASM(configFile)
		if err != nil {
			return nil, err
		}

		return plugin, nil
	})
}

type getFunc func(namespace, name string) (metav1.ObjectMetaAccessor, error)

type Plugin struct {
	serializer runtime.Serializer
	plugin     wasmplugin.Validation
	m          sync.Mutex
	authorizer authorizer.Authorizer
	informers  map[metav1.GroupVersionResource]getFunc
}

var _ interface {
	// the required interfaces
	admission.Interface
	admission.ValidationInterface
	admission.InitializationValidator

	// things that I am pretty sure we want
	initializer.WantsAuthorizer
	initializer.WantsExternalKubeInformerFactory
	initializer.WantsDrainedNotification
	// TODO need to pass in logger to the plugin

	// things that I am less sure about
	initializer.WantsFeatures
	initializer.WantsQuotaConfiguration
	initializer.WantsExternalKubeClientSet
} = &Plugin{}

func NewValidatingAdmissionWASM(configFile io.Reader) (*Plugin, error) {
	scheme := runtime.NewScheme()
	if err := admissionv1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	ctx := context.Background()

	wasmPluginLoader, err := wasmplugin.NewValidationPlugin(ctx, wasmplugin.ValidationPluginOption{})
	if err != nil {
		return nil, err
	}

	admissionPlugin := &Plugin{
		// legacy should always use JSON
		serializer: serializer.NewCodecFactory(scheme).LegacyCodec(admissionv1.SchemeGroupVersion),
	}

	wasmPlugin, err := wasmPluginLoader.Load(ctx, "/home/mo/plugin.wasm", admissionPlugin)
	if err != nil {
		return nil, err
	}
	admissionPlugin.plugin = wasmPlugin

	return admissionPlugin, nil
}

func (p *Plugin) Validate(ctx context.Context, attr admission.Attributes, o admission.ObjectInterfaces) error {
	// TODO better filter
	if attr.GetNamespace() != "mo-wasm" {
		return nil
	}
	if attr.GetName() != "mo-wasm" {
		return nil
	}

	name := "mo-wasm-plugin"

	invocation := &generic.WebhookInvocation{
		Resource:    attr.GetResource(),
		Subresource: attr.GetSubresource(),
		Kind:        attr.GetKind(),
	}

	versionedAttr, err := generic.NewVersionedAttributes(attr, invocation.Kind, o)
	if err != nil {
		return apierrors.NewInternalError(err)
	}

	// make mutation of input impossible
	if versionedAttr.VersionedOldObject != nil {
		versionedAttr.VersionedOldObject = versionedAttr.VersionedOldObject.DeepCopyObject()
	}
	if versionedAttr.VersionedObject != nil {
		versionedAttr.VersionedObject = versionedAttr.VersionedObject.DeepCopyObject()
	}

	uid := uuid.NewUUID()

	req := request.CreateV1AdmissionReview(uid, versionedAttr, invocation)

	// TODO this is silly, we should send proper structured data, not bytes
	buf, err := runtime.Encode(p.serializer, req)
	if err != nil {
		return err
	}
	validateResponse, err := p.validate(ctx, buf)
	if err != nil {
		return err
	}
	resp := &admissionv1.AdmissionReview{}
	if err := runtime.DecodeInto(p.serializer, validateResponse.AdmissionReview, resp); err != nil {
		return err
	}

	result, err := webhookrequest.VerifyAdmissionResponse(uid, false, resp)
	if err != nil {
		return err
	}

	for k, v := range result.AuditAnnotations {
		key := name + "/" + k
		if err := versionedAttr.Attributes.AddAnnotation(key, v); err != nil {
			klog.Warningf("Failed to set admission audit annotation %s to %s for wasm plugin %s: %v", key, v, name, err)
		}
	}
	for _, w := range result.Warnings {
		warning.AddWarning(ctx, "", w)
	}
	if result.Allowed {
		return nil
	}
	return &webhookutil.ErrWebhookRejection{Status: webhookerrors.ToStatusErr(name, result.Result)}

}

func (p *Plugin) Handles(_ admission.Operation) bool {
	return true // handled by each plugin individually
}

func (p *Plugin) ValidateInitialization() error {
	if p.authorizer == nil {
		return fmt.Errorf("wasm plugin missing authorizer")
	}

	if p.informers == nil {
		return fmt.Errorf("wasm plugin missing informers")
	}

	// TODO implement the rest
	return nil
}

func (p *Plugin) SetAuthorizer(authorizer authorizer.Authorizer) {
	p.authorizer = authorizer
}

func (p *Plugin) InspectFeatureGates(gate featuregate.FeatureGate) {
	// TODO implement
}

func (p *Plugin) SetQuotaConfiguration(q quota.Configuration) {
	// TODO implement
}

func (p *Plugin) SetDrainedNotification(stopCh <-chan struct{}) {
	// TODO implement
}

func (p *Plugin) SetExternalKubeClientSet(client kubernetes.Interface) {
	// TODO implement
}

func (p *Plugin) SetExternalKubeInformerFactory(informers informers.SharedInformerFactory) {
	// informers are lazily loaded so we need to call these outside of the closure
	namespaceInformer := informers.Core().V1().Namespaces().Lister()
	podInformer := informers.Core().V1().Pods().Lister()
	configmapInformer := informers.Core().V1().ConfigMaps().Lister()

	p.informers = map[metav1.GroupVersionResource]getFunc{
		metav1.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		}: func(namespace, name string) (metav1.ObjectMetaAccessor, error) {
			if len(namespace) > 0 {
				return nil, fmt.Errorf("namespace resource is cluster scoped: %s", namespace)
			}
			return namespaceInformer.Get(name)
		},
		metav1.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		}: func(namespace, name string) (metav1.ObjectMetaAccessor, error) {
			return podInformer.Pods(namespace).Get(name)
		},
		metav1.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "configmaps",
		}: func(namespace, name string) (metav1.ObjectMetaAccessor, error) {
			return configmapInformer.ConfigMaps(namespace).Get(name)
		},
	}
}

func (p *Plugin) validate(ctx context.Context, buf []byte) (wasmplugin.ValidateResponse, error) {
	p.m.Lock()
	defer p.m.Unlock()

	return p.plugin.Validate(ctx, wasmplugin.ValidateRequest{AdmissionReview: buf})
}

func (p *Plugin) Authorizer(ctx context.Context, spec wasmplugin.SubjectAccessReviewSpec) (wasmplugin.SubjectAccessReviewStatus, error) { // TODO mutex copy error
	// TODO need more attributes
	attr := authorizer.AttributesRecord{
		User: &user.DefaultInfo{
			Name:   spec.Username,
			Groups: spec.Groups,
		},
		Verb:            spec.Verb,
		Resource:        spec.Resource,
		ResourceRequest: true,
	}

	decision, reason, err := p.authorizer.Authorize(ctx, attr)

	return wasmplugin.SubjectAccessReviewStatus{
		Allowed: decision == authorizer.DecisionAllow,
		Reason:  reason,
	}, err // this error causes a panic which is caught
}

func (p *Plugin) Informer(ctx context.Context, informerRequest wasmplugin.InformerRequest) (wasmplugin.InformerResponse, error) {
	gvr := metav1.GroupVersionResource{
		Group:    informerRequest.Group,
		Version:  informerRequest.Version,
		Resource: informerRequest.Resource,
	}
	f := p.informers[gvr]
	if f == nil {
		return wasmplugin.InformerResponse{}, fmt.Errorf("invalid gvr: %s", gvr)
	}
	meta, err := f(informerRequest.Namespace, informerRequest.Name)
	if err != nil {
		return wasmplugin.InformerResponse{}, err
	}
	o := meta.GetObjectMeta()
	return wasmplugin.InformerResponse{
		Namespace:         o.GetNamespace(),
		Name:              o.GetName(),
		ResourceVersion:   o.GetResourceVersion(),
		CreationTimestamp: o.GetCreationTimestamp().String(),
		Labels:            o.GetLabels(),
	}, nil
}
