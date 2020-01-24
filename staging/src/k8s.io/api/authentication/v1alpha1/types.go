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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthenticationConfig struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec AuthenticationConfigSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`

	// +optional
	Status AuthenticationConfigStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

type AuthenticationConfigSpec struct {
	Type AuthenticationConfigType `json:"type" protobuf:"bytes,1,opt,name=type"`

	X509 *X509Config `json:"x509,omitempty" protobuf:"bytes,2,opt,name=x509"`

	OIDC *OIDCConfig `json:"oidc,omitempty" protobuf:"bytes,3,opt,name=oidc"`

	Webhook *WebhookConfig `json:"webhook,omitempty" protobuf:"bytes,4,opt,name=webhook"`
}

type AuthenticationConfigStatus struct {
	// TODO needed?
}

type AuthenticationConfigType string

const (
	AuthenticationConfigTypeX509    AuthenticationConfigType = "x509"
	AuthenticationConfigTypeOIDC    AuthenticationConfigType = "oidc"
	AuthenticationConfigTypeWebhook AuthenticationConfigType = "webhook"
)

type X509Config struct {
	// TODO do we need this with the recent CSR API signer changes?
	// TODO fill in
}

type OIDCConfig struct {
	Issuer string `json:"issuer" protobuf:"bytes,1,opt,name=issuer"`

	ClientID string `json:"clientID" protobuf:"bytes,2,opt,name=clientID"`

	UsernameClaim string `json:"usernameClaim" protobuf:"bytes,3,opt,name=usernameClaim"`

	// TODO complete
}

type WebhookConfig struct {
	// TODO fill in
}
