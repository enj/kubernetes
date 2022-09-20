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
	"bytes"
	"context"
	"fmt"
	"io"

	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

type Plugin struct {
	serializer runtime.Serializer
	plugin     wasmplugin.Validation
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

	p, err := wasmplugin.NewValidationPlugin(ctx, wasmplugin.ValidationPluginOption{})
	if err != nil {
		return nil, err
	}

	plugin, err := p.Load(ctx, "path/to/plugin.wasm")
	if err != nil {
		return nil, err
	}

	return &Plugin{
		// legacy should always use JSON
		serializer: serializer.NewCodecFactory(scheme).LegacyCodec(admissionv1.SchemeGroupVersion),
		plugin:     plugin,
	}, nil
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
	versionedAttr.VersionedOldObject = versionedAttr.VersionedOldObject.DeepCopyObject()
	versionedAttr.VersionedObject = versionedAttr.VersionedObject.DeepCopyObject()

	uid := uuid.NewUUID()

	req := request.CreateV1AdmissionReview(uid, versionedAttr, invocation)

	// TODO this is silly, we should send proper structured data, not bytes
	buf, err := encodeObject(req, p.serializer)
	if err != nil {
		return err
	}
	validateResponse, err := p.plugin.Validate(ctx, wasmplugin.ValidateRequest{AdmissionReview: buf})
	if err != nil {
		return err
	}
	resp, err := decodeObject(validateResponse.AdmissionReview, p.serializer)
	if err != nil {
		return err
	}

	resp.Response.UID = uid // TODO fix
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
	// TODO implement
	return nil
}

func (p *Plugin) SetAuthorizer(authorizer authorizer.Authorizer) {
	// TODO implement
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

func (p *Plugin) SetExternalKubeInformerFactory(factory informers.SharedInformerFactory) {
	// TODO implement
}

func encodeObject(obj runtime.Object, serializer runtime.Serializer) ([]byte, error) {
	var buf bytes.Buffer
	if err := serializer.Encode(obj, &buf); err != nil {
		return nil, fmt.Errorf("encoding failed: %v", err)
	}

	return buf.Bytes(), nil
}

func decodeObject(data []byte, serializer runtime.Serializer) (*admissionv1.AdmissionReview, error) {
	resp := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: true, // TODO fix
		},
	}

	// TODO fix
	if false {
		_, _, err := serializer.Decode(data, nil, resp)
		if err != nil {
			return nil, fmt.Errorf("decoding failed: %v", err)
		}
	}

	return resp, nil
}
