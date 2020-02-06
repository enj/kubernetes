/*
Copyright 2016 The Kubernetes Authors.

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

package authentication

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// ImpersonateUserHeader is used to impersonate a particular user during an API server request
	ImpersonateUserHeader = "Impersonate-User"

	// ImpersonateGroupHeader is used to impersonate a particular group during an API server request.
	// It can be repeated multiplied times for multiple groups.
	ImpersonateGroupHeader = "Impersonate-Group"

	// ImpersonateUserExtraHeaderPrefix is a prefix for any header used to impersonate an entry in the
	// extra map[string][]string for user.Info.  The key will be every after the prefix.
	// It can be repeated multiplied times for multiple map keys and the same key can be repeated multiple
	// times to have multiple elements in the slice under a single key
	ImpersonateUserExtraHeaderPrefix = "Impersonate-Extra-"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TokenReview attempts to authenticate a token to a known user.
type TokenReview struct {
	metav1.TypeMeta
	// ObjectMeta fulfills the metav1.ObjectMetaAccessor interface so that the stock
	// REST handler paths work
	metav1.ObjectMeta

	// Spec holds information about the request being evaluated
	Spec TokenReviewSpec

	// Status is filled in by the server and indicates whether the request can be authenticated.
	Status TokenReviewStatus
}

// TokenReviewSpec is a description of the token authentication request.
type TokenReviewSpec struct {
	// Token is the opaque bearer token.
	Token string
	// Audiences is a list of the identifiers that the resource server presented
	// with the token identifies as. Audience-aware token authenticators will
	// verify that the token was intended for at least one of the audiences in
	// this list. If no audiences are provided, the audience will default to the
	// audience of the Kubernetes apiserver.
	Audiences []string
}

// TokenReviewStatus is the result of the token authentication request.
// This type mirrors the authentication.Token interface
type TokenReviewStatus struct {
	// Authenticated indicates that the token was associated with a known user.
	Authenticated bool
	// User is the UserInfo associated with the provided token.
	User UserInfo
	// Audiences are audience identifiers chosen by the authenticator that are
	// compatible with both the TokenReview and token. An identifier is any
	// identifier in the intersection of the TokenReviewSpec audiences and the
	// token's audiences. A client of the TokenReview API that sets the
	// spec.audiences field should validate that a compatible audience identifier
	// is returned in the status.audiences field to ensure that the TokenReview
	// server is audience aware. If a TokenReview returns an empty
	// status.audience field where status.authenticated is "true", the token is
	// valid against the audience of the Kubernetes API server.
	Audiences []string
	// Error indicates that the token couldn't be checked
	Error string
}

// UserInfo holds the information about the user needed to implement the
// user.Info interface.
type UserInfo struct {
	// The name that uniquely identifies this user among all active users.
	Username string
	// A unique value that identifies this user across time. If this user is
	// deleted and another user by the same name is added, they will have
	// different UIDs.
	UID string
	// The names of groups this user is a part of.
	Groups []string
	// Any additional information provided by the authenticator.
	Extra map[string]ExtraValue
}

// ExtraValue masks the value so protobuf can generate
type ExtraValue []string

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TokenRequest requests a token for a given service account.
type TokenRequest struct {
	metav1.TypeMeta
	// ObjectMeta fulfills the metav1.ObjectMetaAccessor interface so that the stock
	// REST handler paths work
	metav1.ObjectMeta

	Spec   TokenRequestSpec
	Status TokenRequestStatus
}

// TokenRequestSpec contains client provided parameters of a token request.
type TokenRequestSpec struct {
	// Audiences are the intendend audiences of the token. A recipient of a
	// token must identify themself with an identifier in the list of
	// audiences of the token, and otherwise should reject the token. A
	// token issued for multiple audiences may be used to authenticate
	// against any of the audiences listed but implies a high degree of
	// trust between the target audiences.
	Audiences []string

	// ExpirationSeconds is the requested duration of validity of the request. The
	// token issuer may return a token with a different validity duration so a
	// client needs to check the 'expiration' field in a response.
	ExpirationSeconds int64

	// BoundObjectRef is a reference to an object that the token will be bound to.
	// The token will only be valid for as long as the bound object exists.
	// NOTE: The API server's TokenReview endpoint will validate the
	// BoundObjectRef, but other audiences may not. Keep ExpirationSeconds
	// small if you want prompt revocation.
	BoundObjectRef *BoundObjectReference
}

// TokenRequestStatus is the result of a token request.
type TokenRequestStatus struct {
	// Token is the opaque bearer token.
	Token string
	// ExpirationTimestamp is the time of expiration of the returned token.
	ExpirationTimestamp metav1.Time
}

// BoundObjectReference is a reference to an object that a token is bound to.
type BoundObjectReference struct {
	// Kind of the referent. Valid kinds are 'Pod' and 'Secret'.
	Kind string
	// API version of the referent.
	APIVersion string

	// Name of the referent.
	Name string
	// UID of the referent.
	UID types.UID
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthenticationConfig struct {
	metav1.TypeMeta
	// +optional
	metav1.ObjectMeta

	Spec AuthenticationConfigSpec

	// +optional
	Status AuthenticationConfigStatus
}

type AuthenticationConfigSpec struct {
	Type AuthenticationConfigType

	X509 *X509Config

	OIDC *OIDCConfig

	Webhook *WebhookConfig

	// TODO decide if this needs to be a pointer or not
	// TODO this may only make sense for the webhook type
	ServerAuthentication *ServerAuthentication

	// TODO this may only make sense for the webhook type
	// ClientConfig defines how to communicate with the hook.
	// Required
	ClientConfig WebhookClientConfig
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
	CABundle []byte
}

type OIDCConfig struct {
	Issuer string

	ClientID string

	UsernameClaim string

	// TODO complete
}

type WebhookConfig struct {
	// TODO fill in
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationConfigList is a list of AuthenticationConfig.
type AuthenticationConfigList struct {
	metav1.TypeMeta
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
	// +optional
	metav1.ListMeta
	// List of AuthenticationConfig.
	// +listType=set
	Items []AuthenticationConfig
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
	URL *string

	// `service` is a reference to the service for this webhook. Either
	// `service` or `url` must be specified.
	//
	// If the webhook is running within the cluster, then you should use `service`.
	//
	// +optional
	Service *ServiceReference

	// `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
	// If unspecified, system trust roots on the apiserver are used.
	// +optional
	// +listType=atomic
	CABundle []byte
}

// ServiceReference holds a reference to Service.legacy.k8s.io
type ServiceReference struct {
	// `namespace` is the namespace of the service.
	// Required
	Namespace string
	// `name` is the name of the service.
	// Required
	Name string

	// `path` is an optional URL path which will be sent in any request to
	// this service.
	// +optional
	Path *string

	// If specified, the port on the service that hosting webhook.
	// Default to 443 for backward compatibility.
	// `port` should be a valid port number (1-65535, inclusive).
	// +optional
	Port *int32
}
