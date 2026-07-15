/*
Copyright 2018 The Kubernetes Authors.

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

// Package validation contains methods to validate kinds in the
// authentication.k8s.io API group.
package validation

import (
	"fmt"
	"regexp"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/authentication"
)

const MinTokenAgeSec = 10 * 60 // 10 minutes

var regexpWebhookConfigurationKind = regexp.MustCompile(`(Validating|Mutating)WebhookConfiguration`)

// ValidateTokenRequest validates a TokenRequest.
func ValidateTokenRequest(tr *authentication.TokenRequest) field.ErrorList {
	allErrs := field.ErrorList{}
	specPath := field.NewPath("spec")

	if tr.Spec.ExpirationSeconds < MinTokenAgeSec {
		allErrs = append(allErrs, field.Invalid(specPath.Child("expirationSeconds"), tr.Spec.ExpirationSeconds, "may not specify a duration less than 10 minutes"))
	}
	if tr.Spec.ExpirationSeconds > 1<<32 {
		allErrs = append(allErrs, field.Invalid(specPath.Child("expirationSeconds"), tr.Spec.ExpirationSeconds, "may not specify a duration larger than 2^32 seconds"))

	}

	allErrs = append(allErrs, validateAttestations(tr, specPath.Child("attestations"))...)
	if isWebhookConfig(tr.Spec.BoundObjectRef.Kind) && len(tr.Spec.Audiences) != 1 {
		allErrs = append(allErrs, field.Invalid(specPath, tr.Spec.Audiences, "must be length 1"))
	}

	return allErrs
}

func validateAttestations(tr *authentication.TokenRequest, specPath *field.Path) field.ErrorList {
	attestations := tr.Spec.Attestations
	boundObjectRef := tr.Spec.BoundObjectRef

	// Attestations require a bound object reference.
	if boundObjectRef == nil {
		if len(attestations) == 0 {
			return nil
		}
		return field.ErrorList{field.Invalid(specPath, "", "attestations may not be specified without a bound object reference")}
	}

	if !isWebhookConfig(tr.Spec.BoundObjectRef.Kind) {
		if len(attestations) == 0 {
			return nil
		}
		return field.ErrorList{field.Invalid(specPath, boundObjectRef.Kind, fmt.Sprintf("attestations may not be specified when bound object ref is of kind %s", boundObjectRef.Kind))}
	}

	if len(attestations) == 0 {
		return field.ErrorList{field.Invalid(specPath, attestations, "may not be empty when bound object is webhook configuration")}
	}

	if _, ok := tr.Spec.Attestations[authentication.AttestationAdmissionReviewAPIGroups]; !ok {
		return field.ErrorList{field.Invalid(specPath, attestations, fmt.Sprintf("attestation %q is required when bound object is a webhook configuration", authentication.AttestationAdmissionReviewAPIGroups))}
	}

	errs := field.ErrorList{}
	for key, values := range attestations {
		errs = append(errs, validateValues(key, values, specPath)...)
	}

	return errs
}

func validateValues(key string, values authentication.AttestationValue, specPath *field.Path) field.ErrorList {
	if len(values) == 0 {
		return field.ErrorList{field.Invalid(specPath, key, "may not specify empty value")}
	}

	switch key {
	case authentication.AttestationAdmissionReviewAPIGroups:
		if len(values) != 1 {
			return field.ErrorList{field.Invalid(specPath.Child(authentication.AttestationAdmissionReviewAPIGroups), key, "must specify a single value")}
		}

		return validateAdmissionReviewAPIGroupsValue(values[0], specPath.Child(authentication.AttestationAdmissionReviewAPIGroups))
	default:
		return field.ErrorList{field.Invalid(specPath, key, "may not specify an unknown key")}
	}
}

func validateAdmissionReviewAPIGroupsValue(group string, specPath *field.Path) field.ErrorList {
	var errs field.ErrorList

	// The value "" cannot be allowed for the "admissionReviewAPIGroups"
	// because "" means two different things depending on the context in
	// which it is presented. In the context of a resource name in an
	// authorization request, "" means "all resource names". In the
	// context of an API Group, "" means "the core API group".
	//
	// The only valid requester of an admission review token for the
	// core API group is the Kubernetes API Server itself. Kubernetes
	// API Server will always use "admissionReviewAPIGroups": "*" when
	// it needs a token to authenticate to a webhook, so there is never
	// a need to allow the value "" for this attestation.
	if len(group) == 0 {
		errs = append(errs, field.Invalid(specPath, group, "may not be an empty string"))
		return errs
	}

	if group == "*" {
		return nil
	}

	// valid label, e.g. "apps"
	labelReasons := validation.IsDNS1123Label(group)
	if len(labelReasons) == 0 {
		return nil
	}

	// valid subdomain, e.g. "admissionregistration.k8s.io"
	subdomainReasons := validation.IsDNS1123Subdomain(group)
	if len(subdomainReasons) == 0 {
		return nil
	}

	allReasons := append(labelReasons, subdomainReasons...)
	for _, reason := range allReasons {
		errs = append(errs, field.Invalid(specPath, group, "must specify a valid API Group: "+reason))
	}

	return errs
}

func isWebhookConfig(s string) bool {
	return regexpWebhookConfigurationKind.MatchString(s)
}
