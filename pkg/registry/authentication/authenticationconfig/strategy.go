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

package authenticationconfig

import (
	"context"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/authentication"
	"k8s.io/kubernetes/pkg/apis/authentication/validation"
)

type authenticationConfigStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

var Strategy = authenticationConfigStrategy{legacyscheme.Scheme, names.SimpleNameGenerator}

func (authenticationConfigStrategy) NamespaceScoped() bool {
	return false
}

func (authenticationConfigStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	authenticationConfig := obj.(*authentication.AuthenticationConfig)
	authenticationConfig.Generation = 1
}

func (authenticationConfigStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newAuthenticationConfig := obj.(*authentication.AuthenticationConfig)
	oldAuthenticationConfig := old.(*authentication.AuthenticationConfig)

	// Any changes to the spec increment the generation number, any changes to the
	// status should reflect the generation number of the corresponding object.
	// See metav1.ObjectMeta description for more information on Generation.
	if !reflect.DeepEqual(oldAuthenticationConfig.Spec, newAuthenticationConfig.Spec) {
		newAuthenticationConfig.Generation = oldAuthenticationConfig.Generation + 1
	}
}

func (authenticationConfigStrategy) Canonicalize(obj runtime.Object) {
}

func (authenticationConfigStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (authenticationConfigStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (authenticationConfigStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validation.ValidateAuthenticationConfig(obj.(*authentication.AuthenticationConfig))
}

func (authenticationConfigStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return validation.ValidateAuthenticationConfigUpdate(obj.(*authentication.AuthenticationConfig), old.(*authentication.AuthenticationConfig))
}
