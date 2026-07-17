/*
Copyright 2025 The Kubernetes Authors.

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

package rest

import (
	"context"

	admissionregistrationv1api "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	applyconfigurationsadmissionregistrationv1 "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
	admissionregistrationv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	restclient "k8s.io/client-go/rest"
)

// notFoundAdmissionRegistrationClient implements AdmissionregistrationV1Interface
// and returns not-found errors for all resource operations. This parallels the
// notFoundGetter pattern used elsewhere in this package.
type notFoundAdmissionRegistrationClient struct{}

func newNotFoundAdmissionRegistrationClient() admissionregistrationv1.AdmissionregistrationV1Interface {
	return &notFoundAdmissionRegistrationClient{}
}

func (c *notFoundAdmissionRegistrationClient) RESTClient() restclient.Interface { return nil }
func (c *notFoundAdmissionRegistrationClient) MutatingAdmissionPolicies() admissionregistrationv1.MutatingAdmissionPolicyInterface {
	return &notFoundMutatingAdmissionPolicies{}
}
func (c *notFoundAdmissionRegistrationClient) MutatingAdmissionPolicyBindings() admissionregistrationv1.MutatingAdmissionPolicyBindingInterface {
	return &notFoundMutatingAdmissionPolicyBindings{}
}
func (c *notFoundAdmissionRegistrationClient) MutatingWebhookConfigurations() admissionregistrationv1.MutatingWebhookConfigurationInterface {
	return &notFoundMutatingWebhookConfigurations{}
}
func (c *notFoundAdmissionRegistrationClient) ValidatingAdmissionPolicies() admissionregistrationv1.ValidatingAdmissionPolicyInterface {
	return &notFoundValidatingAdmissionPolicies{}
}
func (c *notFoundAdmissionRegistrationClient) ValidatingAdmissionPolicyBindings() admissionregistrationv1.ValidatingAdmissionPolicyBindingInterface {
	return &notFoundValidatingAdmissionPolicyBindings{}
}
func (c *notFoundAdmissionRegistrationClient) ValidatingWebhookConfigurations() admissionregistrationv1.ValidatingWebhookConfigurationInterface {
	return &notFoundValidatingWebhookConfigurations{}
}

var (
	mutatingWebhookConfigurationGR     = schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingwebhookconfigurations"}
	validatingWebhookConfigurationGR   = schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingwebhookconfigurations"}
	mutatingAdmissionPolicyGR          = schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingadmissionpolicies"}
	mutatingAdmissionPolicyBindingGR   = schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingadmissionpolicybindings"}
	validatingAdmissionPolicyGR        = schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicies"}
	validatingAdmissionPolicyBindingGR = schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicybindings"}
)

// notFoundMutatingWebhookConfigurations

type notFoundMutatingWebhookConfigurations struct{}

func (n *notFoundMutatingWebhookConfigurations) Create(_ context.Context, _ *admissionregistrationv1api.MutatingWebhookConfiguration, _ metav1.CreateOptions) (*admissionregistrationv1api.MutatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(mutatingWebhookConfigurationGR, "")
}
func (n *notFoundMutatingWebhookConfigurations) Update(_ context.Context, _ *admissionregistrationv1api.MutatingWebhookConfiguration, _ metav1.UpdateOptions) (*admissionregistrationv1api.MutatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(mutatingWebhookConfigurationGR, "")
}
func (n *notFoundMutatingWebhookConfigurations) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	return errors.NewNotFound(mutatingWebhookConfigurationGR, name)
}
func (n *notFoundMutatingWebhookConfigurations) DeleteCollection(_ context.Context, _ metav1.DeleteOptions, _ metav1.ListOptions) error {
	return errors.NewNotFound(mutatingWebhookConfigurationGR, "")
}
func (n *notFoundMutatingWebhookConfigurations) Get(_ context.Context, name string, _ metav1.GetOptions) (*admissionregistrationv1api.MutatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(mutatingWebhookConfigurationGR, name)
}
func (n *notFoundMutatingWebhookConfigurations) List(_ context.Context, _ metav1.ListOptions) (*admissionregistrationv1api.MutatingWebhookConfigurationList, error) {
	return nil, errors.NewNotFound(mutatingWebhookConfigurationGR, "")
}
func (n *notFoundMutatingWebhookConfigurations) Watch(_ context.Context, _ metav1.ListOptions) (watch.Interface, error) {
	return nil, errors.NewNotFound(mutatingWebhookConfigurationGR, "")
}
func (n *notFoundMutatingWebhookConfigurations) Patch(_ context.Context, name string, _ types.PatchType, _ []byte, _ metav1.PatchOptions, _ ...string) (*admissionregistrationv1api.MutatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(mutatingWebhookConfigurationGR, name)
}
func (n *notFoundMutatingWebhookConfigurations) Apply(_ context.Context, _ *applyconfigurationsadmissionregistrationv1.MutatingWebhookConfigurationApplyConfiguration, _ metav1.ApplyOptions) (*admissionregistrationv1api.MutatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(mutatingWebhookConfigurationGR, "")
}

// notFoundValidatingWebhookConfigurations

type notFoundValidatingWebhookConfigurations struct{}

func (n *notFoundValidatingWebhookConfigurations) Create(_ context.Context, _ *admissionregistrationv1api.ValidatingWebhookConfiguration, _ metav1.CreateOptions) (*admissionregistrationv1api.ValidatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(validatingWebhookConfigurationGR, "")
}
func (n *notFoundValidatingWebhookConfigurations) Update(_ context.Context, _ *admissionregistrationv1api.ValidatingWebhookConfiguration, _ metav1.UpdateOptions) (*admissionregistrationv1api.ValidatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(validatingWebhookConfigurationGR, "")
}
func (n *notFoundValidatingWebhookConfigurations) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	return errors.NewNotFound(validatingWebhookConfigurationGR, name)
}
func (n *notFoundValidatingWebhookConfigurations) DeleteCollection(_ context.Context, _ metav1.DeleteOptions, _ metav1.ListOptions) error {
	return errors.NewNotFound(validatingWebhookConfigurationGR, "")
}
func (n *notFoundValidatingWebhookConfigurations) Get(_ context.Context, name string, _ metav1.GetOptions) (*admissionregistrationv1api.ValidatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(validatingWebhookConfigurationGR, name)
}
func (n *notFoundValidatingWebhookConfigurations) List(_ context.Context, _ metav1.ListOptions) (*admissionregistrationv1api.ValidatingWebhookConfigurationList, error) {
	return nil, errors.NewNotFound(validatingWebhookConfigurationGR, "")
}
func (n *notFoundValidatingWebhookConfigurations) Watch(_ context.Context, _ metav1.ListOptions) (watch.Interface, error) {
	return nil, errors.NewNotFound(validatingWebhookConfigurationGR, "")
}
func (n *notFoundValidatingWebhookConfigurations) Patch(_ context.Context, name string, _ types.PatchType, _ []byte, _ metav1.PatchOptions, _ ...string) (*admissionregistrationv1api.ValidatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(validatingWebhookConfigurationGR, name)
}
func (n *notFoundValidatingWebhookConfigurations) Apply(_ context.Context, _ *applyconfigurationsadmissionregistrationv1.ValidatingWebhookConfigurationApplyConfiguration, _ metav1.ApplyOptions) (*admissionregistrationv1api.ValidatingWebhookConfiguration, error) {
	return nil, errors.NewNotFound(validatingWebhookConfigurationGR, "")
}

// notFoundMutatingAdmissionPolicies

type notFoundMutatingAdmissionPolicies struct{}

func (n *notFoundMutatingAdmissionPolicies) Create(_ context.Context, _ *admissionregistrationv1api.MutatingAdmissionPolicy, _ metav1.CreateOptions) (*admissionregistrationv1api.MutatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyGR, "")
}
func (n *notFoundMutatingAdmissionPolicies) Update(_ context.Context, _ *admissionregistrationv1api.MutatingAdmissionPolicy, _ metav1.UpdateOptions) (*admissionregistrationv1api.MutatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyGR, "")
}
func (n *notFoundMutatingAdmissionPolicies) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	return errors.NewNotFound(mutatingAdmissionPolicyGR, name)
}
func (n *notFoundMutatingAdmissionPolicies) DeleteCollection(_ context.Context, _ metav1.DeleteOptions, _ metav1.ListOptions) error {
	return errors.NewNotFound(mutatingAdmissionPolicyGR, "")
}
func (n *notFoundMutatingAdmissionPolicies) Get(_ context.Context, name string, _ metav1.GetOptions) (*admissionregistrationv1api.MutatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyGR, name)
}
func (n *notFoundMutatingAdmissionPolicies) List(_ context.Context, _ metav1.ListOptions) (*admissionregistrationv1api.MutatingAdmissionPolicyList, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyGR, "")
}
func (n *notFoundMutatingAdmissionPolicies) Watch(_ context.Context, _ metav1.ListOptions) (watch.Interface, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyGR, "")
}
func (n *notFoundMutatingAdmissionPolicies) Patch(_ context.Context, name string, _ types.PatchType, _ []byte, _ metav1.PatchOptions, _ ...string) (*admissionregistrationv1api.MutatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyGR, name)
}
func (n *notFoundMutatingAdmissionPolicies) Apply(_ context.Context, _ *applyconfigurationsadmissionregistrationv1.MutatingAdmissionPolicyApplyConfiguration, _ metav1.ApplyOptions) (*admissionregistrationv1api.MutatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyGR, "")
}

// notFoundMutatingAdmissionPolicyBindings

type notFoundMutatingAdmissionPolicyBindings struct{}

func (n *notFoundMutatingAdmissionPolicyBindings) Create(_ context.Context, _ *admissionregistrationv1api.MutatingAdmissionPolicyBinding, _ metav1.CreateOptions) (*admissionregistrationv1api.MutatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundMutatingAdmissionPolicyBindings) Update(_ context.Context, _ *admissionregistrationv1api.MutatingAdmissionPolicyBinding, _ metav1.UpdateOptions) (*admissionregistrationv1api.MutatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundMutatingAdmissionPolicyBindings) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	return errors.NewNotFound(mutatingAdmissionPolicyBindingGR, name)
}
func (n *notFoundMutatingAdmissionPolicyBindings) DeleteCollection(_ context.Context, _ metav1.DeleteOptions, _ metav1.ListOptions) error {
	return errors.NewNotFound(mutatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundMutatingAdmissionPolicyBindings) Get(_ context.Context, name string, _ metav1.GetOptions) (*admissionregistrationv1api.MutatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyBindingGR, name)
}
func (n *notFoundMutatingAdmissionPolicyBindings) List(_ context.Context, _ metav1.ListOptions) (*admissionregistrationv1api.MutatingAdmissionPolicyBindingList, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundMutatingAdmissionPolicyBindings) Watch(_ context.Context, _ metav1.ListOptions) (watch.Interface, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundMutatingAdmissionPolicyBindings) Patch(_ context.Context, name string, _ types.PatchType, _ []byte, _ metav1.PatchOptions, _ ...string) (*admissionregistrationv1api.MutatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyBindingGR, name)
}
func (n *notFoundMutatingAdmissionPolicyBindings) Apply(_ context.Context, _ *applyconfigurationsadmissionregistrationv1.MutatingAdmissionPolicyBindingApplyConfiguration, _ metav1.ApplyOptions) (*admissionregistrationv1api.MutatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(mutatingAdmissionPolicyBindingGR, "")
}

// notFoundValidatingAdmissionPolicies

type notFoundValidatingAdmissionPolicies struct{}

func (n *notFoundValidatingAdmissionPolicies) Create(_ context.Context, _ *admissionregistrationv1api.ValidatingAdmissionPolicy, _ metav1.CreateOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, "")
}
func (n *notFoundValidatingAdmissionPolicies) Update(_ context.Context, _ *admissionregistrationv1api.ValidatingAdmissionPolicy, _ metav1.UpdateOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, "")
}
func (n *notFoundValidatingAdmissionPolicies) UpdateStatus(_ context.Context, _ *admissionregistrationv1api.ValidatingAdmissionPolicy, _ metav1.UpdateOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, "")
}
func (n *notFoundValidatingAdmissionPolicies) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	return errors.NewNotFound(validatingAdmissionPolicyGR, name)
}
func (n *notFoundValidatingAdmissionPolicies) DeleteCollection(_ context.Context, _ metav1.DeleteOptions, _ metav1.ListOptions) error {
	return errors.NewNotFound(validatingAdmissionPolicyGR, "")
}
func (n *notFoundValidatingAdmissionPolicies) Get(_ context.Context, name string, _ metav1.GetOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, name)
}
func (n *notFoundValidatingAdmissionPolicies) List(_ context.Context, _ metav1.ListOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicyList, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, "")
}
func (n *notFoundValidatingAdmissionPolicies) Watch(_ context.Context, _ metav1.ListOptions) (watch.Interface, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, "")
}
func (n *notFoundValidatingAdmissionPolicies) Patch(_ context.Context, name string, _ types.PatchType, _ []byte, _ metav1.PatchOptions, _ ...string) (*admissionregistrationv1api.ValidatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, name)
}
func (n *notFoundValidatingAdmissionPolicies) Apply(_ context.Context, _ *applyconfigurationsadmissionregistrationv1.ValidatingAdmissionPolicyApplyConfiguration, _ metav1.ApplyOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, "")
}
func (n *notFoundValidatingAdmissionPolicies) ApplyStatus(_ context.Context, _ *applyconfigurationsadmissionregistrationv1.ValidatingAdmissionPolicyApplyConfiguration, _ metav1.ApplyOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicy, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyGR, "")
}

// notFoundValidatingAdmissionPolicyBindings

type notFoundValidatingAdmissionPolicyBindings struct{}

func (n *notFoundValidatingAdmissionPolicyBindings) Create(_ context.Context, _ *admissionregistrationv1api.ValidatingAdmissionPolicyBinding, _ metav1.CreateOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundValidatingAdmissionPolicyBindings) Update(_ context.Context, _ *admissionregistrationv1api.ValidatingAdmissionPolicyBinding, _ metav1.UpdateOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundValidatingAdmissionPolicyBindings) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	return errors.NewNotFound(validatingAdmissionPolicyBindingGR, name)
}
func (n *notFoundValidatingAdmissionPolicyBindings) DeleteCollection(_ context.Context, _ metav1.DeleteOptions, _ metav1.ListOptions) error {
	return errors.NewNotFound(validatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundValidatingAdmissionPolicyBindings) Get(_ context.Context, name string, _ metav1.GetOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyBindingGR, name)
}
func (n *notFoundValidatingAdmissionPolicyBindings) List(_ context.Context, _ metav1.ListOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicyBindingList, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundValidatingAdmissionPolicyBindings) Watch(_ context.Context, _ metav1.ListOptions) (watch.Interface, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyBindingGR, "")
}
func (n *notFoundValidatingAdmissionPolicyBindings) Patch(_ context.Context, name string, _ types.PatchType, _ []byte, _ metav1.PatchOptions, _ ...string) (*admissionregistrationv1api.ValidatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyBindingGR, name)
}
func (n *notFoundValidatingAdmissionPolicyBindings) Apply(_ context.Context, _ *applyconfigurationsadmissionregistrationv1.ValidatingAdmissionPolicyBindingApplyConfiguration, _ metav1.ApplyOptions) (*admissionregistrationv1api.ValidatingAdmissionPolicyBinding, error) {
	return nil, errors.NewNotFound(validatingAdmissionPolicyBindingGR, "")
}
