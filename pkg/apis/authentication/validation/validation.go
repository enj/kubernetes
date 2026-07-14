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

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/authentication"
)

const MinTokenAgeSec = 10 * 60 // 10 minutes

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
	attestErrs := validateAttestations(tr.Spec.Attestations, tr.Spec.BoundObjectRef, specPath)
	return append(allErrs, attestErrs...)
}

func validateAttestations(attestations map[string]authentication.AttestationValue, boundObjectRef *authentication.BoundObjectReference, specPath *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	if len(attestations) == 0 {
		return errs
	}

	// Attestations require a webhook-type bound object reference.
	if boundObjectRef == nil {
		errs = append(errs, field.Invalid(specPath.Child("attestations"), "", "attestations may not be specified without a bound object reference"))
		return errs
	}
	switch boundObjectRef.Kind {
	case "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration":
		// allowed
	default:
		errs = append(errs, field.Invalid(specPath.Child("attestations"), boundObjectRef.Kind, fmt.Sprintf("attestations may not be specified when bound object ref is of kind %s", boundObjectRef.Kind)))
		return errs
	}

	for key, values := range attestations {
		if len(values) == 0 {
			errs = append(errs, field.Invalid(specPath.Child("attestations"), key, "may not specify empty value"))
			continue
		}

		switch key {
		case authentication.AttestationAdmissionReviewAPIGroups:
			if len(values) != 1 {
				errs = append(errs, field.Invalid(specPath.Child("attestations").Child(authentication.AttestationAdmissionReviewAPIGroups), key, "must specify a single value"))
				continue
			}

			valueErrs := validateAdmissionReviewAPIGroupsValue(values[0], specPath, key)
			errs = append(errs, valueErrs...)
		default:
			errs = append(errs, field.Invalid(specPath.Child("attestations"), key, "may not specify an unknown key"))
		}
	}

	return errs
}

func validateAdmissionReviewAPIGroupsValue(group string, specPath *field.Path, key string) field.ErrorList {
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
		errs = append(errs, field.Invalid(specPath.Child("attestations").Child(authentication.AttestationAdmissionReviewAPIGroups), key, "may not be an empty string"))
		return errs
	}

	if group == "*" {
		return nil
	}

	// valid label, e.g. "apps"
	labelErrs := validation.IsDNS1123Label(group)
	if len(labelErrs) == 0 {
		return nil
	}

	// valid subdomain, e.g. "admissionregistration.k8s.io"
	subdomainErrs := validation.IsDNS1123Subdomain(group)
	if len(subdomainErrs) == 0 {
		return nil
	}

	allErrs := append(labelErrs, subdomainErrs...)
	for _, err := range allErrs {
		errs = append(errs, field.Invalid(specPath.Child("attestations").Child(authentication.AttestationAdmissionReviewAPIGroups).Child(key), err, "must specify a valid API Group"))
	}

	return errs
}
