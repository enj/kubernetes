/*
Copyright 2024 The Kubernetes Authors.

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

// TODO(aramase): delete this
package cel

import (
	celgo "github.com/google/cel-go/cel"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
)

type ExpressionAccessor interface {
	GetExpression() string
	ReturnTypes() []*celgo.Type
}

var _ ExpressionAccessor = &ConditionalClusterRoleBindingMatchCondition{}

// ConditionalClusterRoleBindingMatchCondition is a CEL expression that maps a ConditionalClusterRoleBinding request to a list of values.
type ConditionalClusterRoleBindingMatchCondition struct {
	Expression string
}

func (v *ConditionalClusterRoleBindingMatchCondition) GetExpression() string {
	return v.Expression
}

func (v *ConditionalClusterRoleBindingMatchCondition) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}

type ConditionalAttributes interface {
	// GetUser returns the user.Info object to authorize
	GetUser() user.Info

	// The namespace of the object, if a request is for a REST object.
	GetNamespace() string

	// GetName returns the name of the object as parsed off the request.  This will not be present for all request types, but
	// will be present for: get, update, delete
	GetName() string

	// IsResourceRequest returns true for requests to API resources, like /api/v1/nodes,
	// and false for non-resource endpoints like /api, /healthz
	IsResourceRequest() bool

	// GetFieldSelector is lazy, thread-safe, and stores the parsed result and error.
	// It returns an error if the field selector cannot be parsed.
	// The returned requirements must be treated as readonly and not modified.
	GetFieldSelector() (fields.Requirements, error)

	// GetLabelSelector is lazy, thread-safe, and stores the parsed result and error.
	// It returns an error if the label selector cannot be parsed.
	// The returned requirements must be treated as readonly and not modified.
	GetLabelSelector() (labels.Requirements, error)
}
