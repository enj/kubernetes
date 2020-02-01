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

	// TODO decide if this needs to be a pointer or not
	// TODO this may only make sense for the webhook type
	ServerAuthentication *ServerAuthentication `json:"serverAuthentication,omitempty" protobuf:"bytes,5,opt,name=serverAuthentication"`

	// TODO this may only make sense for the webhook type
	// ClientConfig defines how to communicate with the hook.
	// Required
	ClientConfig WebhookClientConfig `json:"clientConfig" protobuf:"bytes,6,opt,name=clientConfig"`
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
	// caBundle is a PEM encoded CA bundle used for client auth (x509.ExtKeyUsageClientAuth).
	// +listType=atomic
	// Required
	CABundle []byte `json:"caBundle" protobuf:"bytes,1,opt,name=caBundle"`
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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationConfigList is a list of AuthenticationConfig.
type AuthenticationConfigList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// List of AuthenticationConfig.
	// +listType=set
	Items []AuthenticationConfig `json:"items" protobuf:"bytes,2,rep,name=items"`
}

type ServerAuthentication struct {
	// TODO client cert + key
	// TODO bearer token
}

// TODO these are copied from admission registration

// WebhookClientConfig contains the information to make a TLS
// connection with the webhook
type WebhookClientConfig struct {
	// `url` gives the location of the webhook, in standard URL form
	// (`scheme://host:port/path`). Exactly one of `url` or `service`
	// must be specified.
	//
	// The `host` should not refer to a service running in the cluster; use
	// the `service` field instead. The host might be resolved via external
	// DNS in some apiservers (e.g., `kube-apiserver` cannot resolve
	// in-cluster DNS as that would be a layering violation). `host` may
	// also be an IP address.
	//
	// Please note that using `localhost` or `127.0.0.1` as a `host` is
	// risky unless you take great care to run this webhook on all hosts
	// which run an apiserver which might need to make calls to this
	// webhook. Such installs are likely to be non-portable, i.e., not easy
	// to turn up in a new cluster.
	//
	// The scheme must be "https"; the URL must begin with "https://".
	//
	// A path is optional, and if present may be any string permissible in
	// a URL. You may use the path to pass an arbitrary string to the
	// webhook, for example, a cluster identifier.
	//
	// Attempting to use a user or basic auth e.g. "user:password@" is not
	// allowed. Fragments ("#...") and query parameters ("?...") are not
	// allowed, either.
	//
	// +optional
	URL *string `json:"url,omitempty" protobuf:"bytes,3,opt,name=url"`

	// `service` is a reference to the service for this webhook. Either
	// `service` or `url` must be specified.
	//
	// If the webhook is running within the cluster, then you should use `service`.
	//
	// +optional
	Service *ServiceReference `json:"service,omitempty" protobuf:"bytes,1,opt,name=service"`

	// `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
	// If unspecified, system trust roots on the apiserver are used.
	// +optional
	// +listType=atomic
	CABundle []byte `json:"caBundle,omitempty" protobuf:"bytes,2,opt,name=caBundle"`
}

// ServiceReference holds a reference to Service.legacy.k8s.io
type ServiceReference struct {
	// `namespace` is the namespace of the service.
	// Required
	Namespace string `json:"namespace" protobuf:"bytes,1,opt,name=namespace"`
	// `name` is the name of the service.
	// Required
	Name string `json:"name" protobuf:"bytes,2,opt,name=name"`

	// `path` is an optional URL path which will be sent in any request to
	// this service.
	// +optional
	Path *string `json:"path,omitempty" protobuf:"bytes,3,opt,name=path"`

	// If specified, the port on the service that hosting webhook.
	// Default to 443 for backward compatibility.
	// `port` should be a valid port number (1-65535, inclusive).
	// +optional
	Port *int32 `json:"port,omitempty" protobuf:"varint,4,opt,name=port"`
}
