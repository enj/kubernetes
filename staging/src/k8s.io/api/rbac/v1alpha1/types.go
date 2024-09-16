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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Authorization is calculated against
// 1. evaluation of ClusterRoleBindings - short circuit on match
// 2. evaluation of RoleBindings in the namespace requested - short circuit on match
// 3. deny by default

const (
	APIGroupAll    = "*"
	ResourceAll    = "*"
	VerbAll        = "*"
	NonResourceAll = "*"

	GroupKind          = "Group"
	ServiceAccountKind = "ServiceAccount"
	UserKind           = "User"

	// AutoUpdateAnnotationKey is the name of an annotation which prevents reconciliation if set to "false"
	AutoUpdateAnnotationKey = "rbac.authorization.kubernetes.io/autoupdate"
)

// Authorization is calculated against
// 1. evaluation of ClusterRoleBindings - short circuit on match
// 2. evaluation of RoleBindings in the namespace requested - short circuit on match
// 3. deny by default

// PolicyRule holds information that describes a policy rule, but does not contain information
// about who the rule applies to or which namespace the rule applies to.
type PolicyRule struct {
	// Verbs is a list of Verbs that apply to ALL the ResourceKinds contained in this rule. '*' represents all verbs.
	// +listType=atomic
	Verbs []string `json:"verbs" protobuf:"bytes,1,rep,name=verbs"`

	// APIGroups is the name of the APIGroup that contains the resources.  If multiple API groups are specified, any action requested against one of
	// the enumerated resources in any API group will be allowed. "" represents the core API group and "*" represents all API groups.
	// +optional
	// +listType=atomic
	APIGroups []string `json:"apiGroups,omitempty" protobuf:"bytes,3,rep,name=apiGroups"`
	// Resources is a list of resources this rule applies to. '*' represents all resources.
	// +optional
	// +listType=atomic
	Resources []string `json:"resources,omitempty" protobuf:"bytes,4,rep,name=resources"`
	// ResourceNames is an optional white list of names that the rule applies to.  An empty set means that everything is allowed.
	// +optional
	// +listType=atomic
	ResourceNames []string `json:"resourceNames,omitempty" protobuf:"bytes,5,rep,name=resourceNames"`

	// NonResourceURLs is a set of partial urls that a user should have access to.  *s are allowed, but only as the full, final step in the path
	// Since non-resource URLs are not namespaced, this field is only applicable for ClusterRoles referenced from a ClusterRoleBinding.
	// Rules can either apply to API resources (such as "pods" or "secrets") or non-resource URL paths (such as "/api"),  but not both.
	// +optional
	// +listType=atomic
	NonResourceURLs []string `json:"nonResourceURLs,omitempty" protobuf:"bytes,6,rep,name=nonResourceURLs"`
}

// Subject contains a reference to the object or user identities a role binding applies to.  This can either hold a direct API object reference,
// or a value for non-objects such as user and group names.
type Subject struct {
	// Kind of object being referenced. Values defined by this API group are "User", "Group", and "ServiceAccount".
	// If the Authorizer does not recognized the kind value, the Authorizer should report an error.
	Kind string `json:"kind" protobuf:"bytes,1,opt,name=kind"`
	// APIVersion holds the API group and version of the referenced subject.
	// Defaults to "v1" for ServiceAccount subjects.
	// Defaults to "rbac.authorization.k8s.io/v1alpha1" for User and Group subjects.
	// +k8s:conversion-gen=false
	// +optional
	APIVersion string `json:"apiVersion,omitempty" protobuf:"bytes,2,opt,name=apiVersion"`
	// Name of the object being referenced.
	Name string `json:"name" protobuf:"bytes,3,opt,name=name"`
	// Namespace of the referenced object.  If the object kind is non-namespace, such as "User" or "Group", and this value is not empty
	// the Authorizer should report an error.
	// +optional
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,4,opt,name=namespace"`
}

// RoleRef contains information that points to the role being used
type RoleRef struct {
	// APIGroup is the group for the resource being referenced
	APIGroup string `json:"apiGroup" protobuf:"bytes,1,opt,name=apiGroup"`
	// Kind is the type of resource being referenced
	Kind string `json:"kind" protobuf:"bytes,2,opt,name=kind"`
	// Name is the name of resource being referenced
	Name string `json:"name" protobuf:"bytes,3,opt,name=name"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Role is a namespaced, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding.
// Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 Role, and will no longer be served in v1.22.
type Role struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Rules holds all the PolicyRules for this Role
	// +optional
	// +listType=atomic
	Rules []PolicyRule `json:"rules" protobuf:"bytes,2,rep,name=rules"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RoleBinding references a role, but does not contain it.  It can reference a Role in the same namespace or a ClusterRole in the global namespace.
// It adds who information via Subjects and namespace information by which namespace it exists in.  RoleBindings in a given
// namespace only have effect in that namespace.
// Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 RoleBinding, and will no longer be served in v1.22.
type RoleBinding struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Subjects holds references to the objects the role applies to.
	// +optional
	// +listType=atomic
	Subjects []Subject `json:"subjects,omitempty" protobuf:"bytes,2,rep,name=subjects"`

	// RoleRef can reference a Role in the current namespace or a ClusterRole in the global namespace.
	// If the RoleRef cannot be resolved, the Authorizer must return an error.
	RoleRef RoleRef `json:"roleRef" protobuf:"bytes,3,opt,name=roleRef"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RoleBindingList is a collection of RoleBindings
// Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 RoleBindingList, and will no longer be served in v1.22.
type RoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items is a list of RoleBindings
	Items []RoleBinding `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RoleList is a collection of Roles.
// Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 RoleList, and will no longer be served in v1.22.
type RoleList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items is a list of Roles
	Items []Role `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterRole is a cluster level, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding or ClusterRoleBinding.
// Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 ClusterRole, and will no longer be served in v1.22.
type ClusterRole struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Rules holds all the PolicyRules for this ClusterRole
	// +optional
	// +listType=atomic
	Rules []PolicyRule `json:"rules" protobuf:"bytes,2,rep,name=rules"`

	// AggregationRule is an optional field that describes how to build the Rules for this ClusterRole.
	// If AggregationRule is set, then the Rules are controller managed and direct changes to Rules will be
	// stomped by the controller.
	// +optional
	AggregationRule *AggregationRule `json:"aggregationRule,omitempty" protobuf:"bytes,3,opt,name=aggregationRule"`
}

// AggregationRule describes how to locate ClusterRoles to aggregate into the ClusterRole
type AggregationRule struct {
	// ClusterRoleSelectors holds a list of selectors which will be used to find ClusterRoles and create the rules.
	// If any of the selectors match, then the ClusterRole's permissions will be added
	// +optional
	// +listType=atomic
	ClusterRoleSelectors []metav1.LabelSelector `json:"clusterRoleSelectors,omitempty" protobuf:"bytes,1,rep,name=clusterRoleSelectors"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterRoleBinding references a ClusterRole, but not contain it.  It can reference a ClusterRole in the global namespace,
// and adds who information via Subject.
// Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 ClusterRoleBinding, and will no longer be served in v1.22.
type ClusterRoleBinding struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Subjects holds references to the objects the role applies to.
	// +optional
	// +listType=atomic
	Subjects []Subject `json:"subjects,omitempty" protobuf:"bytes,2,rep,name=subjects"`

	// RoleRef can only reference a ClusterRole in the global namespace.
	// If the RoleRef cannot be resolved, the Authorizer must return an error.
	RoleRef RoleRef `json:"roleRef" protobuf:"bytes,3,opt,name=roleRef"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterRoleBindingList is a collection of ClusterRoleBindings.
// Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 ClusterRoleBindings, and will no longer be served in v1.22.
type ClusterRoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items is a list of ClusterRoleBindings
	Items []ClusterRoleBinding `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterRoleList is a collection of ClusterRoles.
// Deprecated in v1.17 in favor of rbac.authorization.k8s.io/v1 ClusterRoles, and will no longer be served in v1.22.
type ClusterRoleList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items is a list of ClusterRoles
	Items []ClusterRole `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.32

type ConditionalClusterRoleBinding struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// don't need subjects because it is in the conditions

	// Subjects holds references to the objects the role applies to.
	// +optional
	// +listType=atomic
	// Subjects []Subject `json:"subjects,omitempty" protobuf:"bytes,2,rep,name=subjects"`

	// RoleRef can only reference a ClusterRole in the global namespace.
	// If the RoleRef cannot be resolved, the Authorizer must return an error.
	// This field is immutable.
	// RoleRef RoleRef `json:"roleRef" protobuf:"bytes,3,opt,name=roleRef"`
	ClusterRoleName string `json:"clusterRoleName" protobuf:"bytes,1,opt,name=clusterRoleName"`

	// in all cases, expressions must be positively expressed like the rest of RBAC
	// expressions are ANDed together and you need all of them to pass for the binding to apply

	// choice 1, expressions have access to:
	// 1. user info
	// 2. object namespace
	// 3. object name -> if the cluster role has ResourceNames set than we skip this binding altogether
	// 4. selectors
	//
	// I think selectors would be empty if the request didn't express them in a positive way (no NOT support)
	// so both label and field selectors would be expressed as a map[string][]string

	Variables []Variable `json:"variables,omitempty" patchStrategy:"merge" patchMergeKey:"name" protobuf:"bytes,2,rep,name=variables"`

	// need at least one condition expression that checks the user info
	Conditions []Condition `json:"conditions,omitempty" protobuf:"bytes,3,rep,name=conditions"`

	// choice 2 was to split, it was ugly and didn't support variables and I don't really know if it made SRR better
	// because the selector constraints wouldn't be part of SRR without changing that API as well somehow

	// split these in two to handle SelfSubjectRulesReview better
	// RulesFor(user user.Info, namespace string) ([]ResourceRuleInfo, []NonResourceRuleInfo, bool, error)
	// SubjectAndNamespaceConditions []Validation `json:"subjectAndNamespaceConditions,omitempty" protobuf:"bytes,2,rep,name=subjectAndNamespaceConditions"`

	// this would have the rest, which for now would be selectors and object name
	// Conditions []Validation `json:"conditions,omitempty" protobuf:"bytes,3,rep,name=conditions"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.32

// ConditionalClusterRoleBindingList is a collection of ConditionalClusterRoleBindings
type ConditionalClusterRoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items is a list of ConditionalClusterRoleBindings
	Items []ConditionalClusterRoleBinding `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// copy pasted for now, not sure if we need all the fields
// Condition (Validation copy from admission) specifies the CEL expression which is used to apply the validation.
type Condition struct {
	// Expression represents the expression which will be evaluated by CEL.
	// ref: https://github.com/google/cel-spec
	// CEL expressions have access to the contents of the API request/response, organized into CEL variables as well as some other useful variables:
	//
	// - 'object' - The object from the incoming request. The value is null for DELETE requests.
	// - 'oldObject' - The existing object. The value is null for CREATE requests.
	// - 'request' - Attributes of the API request([ref](/pkg/apis/admission/types.go#AdmissionRequest)).
	// - 'params' - Parameter resource referred to by the policy binding being evaluated. Only populated if the policy has a ParamKind.
	// - 'namespaceObject' - The namespace object that the incoming object belongs to. The value is null for cluster-scoped resources.
	// - 'variables' - Map of composited variables, from its name to its lazily evaluated value.
	//   For example, a variable named 'foo' can be accessed as 'variables.foo'.
	// - 'authorizer' - A CEL Authorizer. May be used to perform authorization checks for the principal (user or service account) of the request.
	//   See https://pkg.go.dev/k8s.io/apiserver/pkg/cel/library#Authz
	// - 'authorizer.requestResource' - A CEL ResourceCheck constructed from the 'authorizer' and configured with the
	//   request resource.
	//
	// The `apiVersion`, `kind`, `metadata.name` and `metadata.generateName` are always accessible from the root of the
	// object. No other metadata properties are accessible.
	//
	// Only property names of the form `[a-zA-Z_.-/][a-zA-Z0-9_.-/]*` are accessible.
	// Accessible property names are escaped according to the following rules when accessed in the expression:
	// - '__' escapes to '__underscores__'
	// - '.' escapes to '__dot__'
	// - '-' escapes to '__dash__'
	// - '/' escapes to '__slash__'
	// - Property names that exactly match a CEL RESERVED keyword escape to '__{keyword}__'. The keywords are:
	//	  "true", "false", "null", "in", "as", "break", "const", "continue", "else", "for", "function", "if",
	//	  "import", "let", "loop", "package", "namespace", "return".
	// Examples:
	//   - Expression accessing a property named "namespace": {"Expression": "object.__namespace__ > 0"}
	//   - Expression accessing a property named "x-prop": {"Expression": "object.x__dash__prop > 0"}
	//   - Expression accessing a property named "redact__d": {"Expression": "object.redact__underscores__d > 0"}
	//
	// Equality on arrays with list type of 'set' or 'map' ignores element order, i.e. [1, 2] == [2, 1].
	// Concatenation on arrays with x-kubernetes-list-type use the semantics of the list type:
	//   - 'set': `X + Y` performs a union where the array positions of all elements in `X` are preserved and
	//     non-intersecting elements in `Y` are appended, retaining their partial order.
	//   - 'map': `X + Y` performs a merge where the array positions of all keys in `X` are preserved but the values
	//     are overwritten by values in `Y` when the key sets of `X` and `Y` intersect. Elements in `Y` with
	//     non-intersecting keys are appended, retaining their partial order.
	// Required.
	Expression string `json:"expression" protobuf:"bytes,1,opt,name=Expression"`
	// Message represents the message displayed when validation fails. The message is required if the Expression contains
	// line breaks. The message must not contain line breaks.
	// If unset, the message is "failed rule: {Rule}".
	// e.g. "must be a URL with the host matching spec.host"
	// If the Expression contains line breaks. Message is required.
	// The message must not contain line breaks.
	// If unset, the message is "failed Expression: {Expression}".
	// +optional
	Message string `json:"message,omitempty" protobuf:"bytes,2,opt,name=message"`
	// Reason represents a machine-readable description of why this validation failed.
	// If this is the first validation in the list to fail, this reason, as well as the
	// corresponding HTTP response code, are used in the
	// HTTP response to the client.
	// The currently supported reasons are: "Unauthorized", "Forbidden", "Invalid", "RequestEntityTooLarge".
	// If not set, StatusReasonInvalid is used in the response to the client.
	// +optional
	Reason *metav1.StatusReason `json:"reason,omitempty" protobuf:"bytes,3,opt,name=reason"`
	// messageExpression declares a CEL expression that evaluates to the validation failure message that is returned when this rule fails.
	// Since messageExpression is used as a failure message, it must evaluate to a string.
	// If both message and messageExpression are present on a validation, then messageExpression will be used if validation fails.
	// If messageExpression results in a runtime error, the runtime error is logged, and the validation failure message is produced
	// as if the messageExpression field were unset. If messageExpression evaluates to an empty string, a string with only spaces, or a string
	// that contains line breaks, then the validation failure message will also be produced as if the messageExpression field were unset, and
	// the fact that messageExpression produced an empty string/string with only spaces/string with line breaks will be logged.
	// messageExpression has access to all the same variables as the `expression` except for 'authorizer' and 'authorizer.requestResource'.
	// Example:
	// "object.x must be less than max ("+string(params.max)+")"
	// +optional
	MessageExpression string `json:"messageExpression,omitempty" protobuf:"bytes,4,opt,name=messageExpression"`
}

// Variable is the definition of a variable that is used for composition. A variable is defined as a named expression.
// +structType=atomic
type Variable struct {
	// Name is the name of the variable. The name must be a valid CEL identifier and unique among all variables.
	// The variable can be accessed in other expressions through `variables`
	// For example, if name is "foo", the variable will be available as `variables.foo`
	Name string `json:"name" protobuf:"bytes,1,opt,name=Name"`

	// Expression is the expression that will be evaluated as the value of the variable.
	// The CEL expression has access to the same identifiers as the CEL expressions in Validation.
	Expression string `json:"expression" protobuf:"bytes,2,opt,name=Expression"`
}

/*
These are in CR so less ideal for conditional
type PolicyRule struct {
	// These 3 seem like all things you can easily know statically
	Verbs []string
	APIGroups []string
	Resources []string

	// This is weird sort of conditional thing we support in CRs, maybe need to support in conditional CRB as well
	ResourceNames []string

	// These are already only accessible via CRs / CRBs and IMO don't really matter for conditional
	NonResourceURLs []string
}


Role bindings allow you to make namespace conditional, seems like we want that for conditional CRB as well.


This is already conditional:

type Subject struct {
	// Kind of object being referenced. Values defined by this API group are "User", "Group", and "ServiceAccount".
	// If the Authorizer does not recognized the kind value, the Authorizer should report an error.
	Kind string


	This does not seem useful:
	// APIGroup holds the API group of the referenced subject.
	// Defaults to "" for ServiceAccount subjects.
	// Defaults to "rbac.authorization.k8s.io" for User and Group subjects.
	// +optional
	APIGroup string

	// Name of the object being referenced.
	Name string

	// Namespace of the referenced object.  If the object kind is non-namespace, such as "User" or "Group", and this value is not empty
	// the Authorizer should report an error.
	// +optional
	Namespace string
}



type Attributes interface {
	// YES
	// GetUser returns the user.Info object to authorize
	GetUser() user.Info

	No?
	// GetVerb returns the kube verb associated with API requests (this includes get, list, watch, create, update, patch, delete, deletecollection, and proxy),
	// or the lowercased HTTP verb associated with non-API requests (this includes get, put, post, patch, and delete)
	GetVerb() string

	Dead code for ABAC:
	// When IsReadOnly() == true, the request has no side effects, other than
	// caching, logging, and other incidentals.
	IsReadOnly() bool

	YES
	// The namespace of the object, if a request is for a REST object.
	GetNamespace() string

	No?
	// The kind of object, if a request is for a REST object.
	GetResource() string

	No?
	// GetSubresource returns the subresource being requested, if present
	GetSubresource() string

	Yes?
	// GetName returns the name of the object as parsed off the request.  This will not be present for all request types, but
	// will be present for: get, update, delete
	GetName() string

	No?
	// The group of the resource, if a request is for a REST object.
	GetAPIGroup() string

	Already ignored by RBAC
	// GetAPIVersion returns the version of the group requested, if a request is for a REST object.
	GetAPIVersion() string

	Maybe we would only make resource requests support conditional
	No?
	// IsResourceRequest returns true for requests to API resources, like /api/v1/nodes,
	// and false for non-resource endpoints like /api, /healthz
	IsResourceRequest() bool

	No?
	// GetPath returns the path of the request
	GetPath() string

	YES
	// ParseFieldSelector is lazy, thread-safe, and stores the parsed result and error.
	// It returns an error if the field selector cannot be parsed.
	// The returned requirements must be treated as readonly and not modified.
	GetFieldSelector() (fields.Requirements, error)

	YES
	// ParseLabelSelector is lazy, thread-safe, and stores the parsed result and error.
	// It returns an error if the label selector cannot be parsed.
	// The returned requirements must be treated as readonly and not modified.
	GetLabelSelector() (labels.Requirements, error)
}
*/
