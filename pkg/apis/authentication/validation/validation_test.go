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

package validation

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/apis/authentication"
)

func TestValidateTokenRequestAttestations(t *testing.T) {
	validExpiration := int64(MinTokenAgeSec + 1)

	webhookRef := &authentication.BoundObjectReference{
		Kind:       "ValidatingWebhookConfiguration",
		APIVersion: "admissionregistration.k8s.io/v1",
		Name:       "my-webhook",
		UID:        "uid-123",
	}

	tests := []struct {
		name      string
		tr        *authentication.TokenRequest
		wantErr   string
		expectErr bool
	}{
		{
			name: "valid: no attestations, no bound object",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
				},
			},
		},
		{
			name: "valid: correct admissionReviewAPIGroups with webhook bound object ref",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Audiences:         []string{"https://example.com"},
					BoundObjectRef:    webhookRef,
					Attestations: map[string]authentication.AttestationValue{
						authentication.AttestationAdmissionReviewAPIGroups: {"apps"},
					},
				},
			},
		},
		{
			name: "invalid: empty attestation value",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Audiences:         []string{"https://example.com"},
					BoundObjectRef:    webhookRef,
					Attestations: map[string]authentication.AttestationValue{
						authentication.AttestationAdmissionReviewAPIGroups: {},
					},
				},
			},
			expectErr: true,
			wantErr:   "may not specify empty value",
		},
		{
			name: "invalid: unknown key",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Audiences:         []string{"https://example.com"},
					BoundObjectRef:    webhookRef,
					Attestations: map[string]authentication.AttestationValue{
						authentication.AttestationAdmissionReviewAPIGroups: {"apps"},
						"unknownKey": {"value"},
					},
				},
			},
			expectErr: true,
			wantErr:   "may not specify an unknown key",
		},
		{
			name: "invalid: multiple values for admissionReviewAPIGroups",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Audiences:         []string{"https://example.com"},
					BoundObjectRef: &authentication.BoundObjectReference{
						Kind:       "MutatingWebhookConfiguration",
						APIVersion: "admissionregistration.k8s.io/v1",
						Name:       "my-webhook",
						UID:        "uid-123",
					},
					Attestations: map[string]authentication.AttestationValue{
						authentication.AttestationAdmissionReviewAPIGroups: {"apps", "extensions"},
					},
				},
			},
			expectErr: true,
			wantErr:   "must specify a single value",
		},
		{
			name: "invalid: empty string value",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Audiences:         []string{"https://example.com"},
					BoundObjectRef:    webhookRef,
					Attestations: map[string]authentication.AttestationValue{
						authentication.AttestationAdmissionReviewAPIGroups: {""},
					},
				},
			},
			expectErr: true,
			wantErr:   "may not be an empty string",
		},
		{
			name: "invalid: attestations with Pod bound object",
			tr: &authentication.TokenRequest{
				ObjectMeta: metav1.ObjectMeta{},
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					BoundObjectRef: &authentication.BoundObjectReference{
						Kind:       "Pod",
						APIVersion: "v1",
						Name:       "my-pod",
						UID:        "uid-123",
					},
					Attestations: map[string]authentication.AttestationValue{
						authentication.AttestationAdmissionReviewAPIGroups: {"apps"},
					},
				},
			},
			expectErr: true,
			wantErr:   "attestations may not be specified when bound object ref is of kind Pod",
		},
		{
			name: "invalid: attestations without bound object ref",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Attestations: map[string]authentication.AttestationValue{
						authentication.AttestationAdmissionReviewAPIGroups: {"apps"},
					},
				},
			},
			expectErr: true,
			wantErr:   "attestations may not be specified without a bound object reference",
		},
		{
			name: "invalid: webhook bound object with no attestations",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Audiences:         []string{"https://example.com"},
					BoundObjectRef:    webhookRef,
				},
			},
			expectErr: true,
			wantErr:   "may not be empty when bound object is webhook configuration",
		},
		{
			name: "invalid: webhook bound object missing admissionReviewAPIGroups",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Audiences:         []string{"https://example.com"},
					BoundObjectRef:    webhookRef,
					Attestations: map[string]authentication.AttestationValue{
						"unknownKey": {"value"},
					},
				},
			},
			expectErr: true,
			wantErr:   `attestation "admissionReviewAPIGroups" is required when bound object is a webhook configuration`,
		},
		{
			name: "invalid: multiple audiences with webhook bound object",
			tr: &authentication.TokenRequest{
				Spec: authentication.TokenRequestSpec{
					ExpirationSeconds: validExpiration,
					Audiences:         []string{"https://a.com", "https://b.com"},
					BoundObjectRef:    webhookRef,
					Attestations: map[string]authentication.AttestationValue{
						authentication.AttestationAdmissionReviewAPIGroups: {"apps"},
					},
				},
			},
			expectErr: true,
			wantErr:   "must be length 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateTokenRequest(tt.tr)
			if tt.expectErr {
				if len(errs) == 0 {
					t.Fatalf("expected error containing %q, got none", tt.wantErr)
				}
				found := false
				for _, e := range errs {
					if strings.Contains(e.Error(), tt.wantErr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, got %v", tt.wantErr, errs)
				}
			} else if len(errs) > 0 {
				t.Errorf("unexpected errors: %v", errs)
			}
		})
	}
}
