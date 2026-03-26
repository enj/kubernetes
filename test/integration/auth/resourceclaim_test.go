/*
Copyright The Kubernetes Authors.

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

package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	resourceapi "k8s.io/api/resource/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	kubeapiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/test/integration/authutil"
	"k8s.io/kubernetes/test/integration/framework"
)

func TestResourceClaimGranularStatusAuthorization(t *testing.T) {
	// Enable Feature Gates Globally for the test run
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.DynamicResourceAllocation, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.DRAResourceClaimDeviceStatus, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.DRAResourceClaimGranularStatusAuthorization, true)

	const (
		ns        = "dra-authz-test"
		saName    = "dra-plugin-sa"
		claimName = "test-claim"
		nodeName  = "worker-1"
	)

	testcases := []struct {
		name             string
		preAllocate      bool
		impersonateExtra map[string][]string
		extraRules       []rbacv1.PolicyRule
		updateClaim      func(c *resourceapi.ResourceClaim)
		verifyErr        func(t *testing.T, err error)
	}{
		{
			name:        "fails to update status.devices without driver permission",
			preAllocate: true,
			// No extra RBAC beyond front-door
			updateClaim: func(c *resourceapi.ResourceClaim) {
				c.Status.Devices = []resourceapi.AllocatedDeviceStatus{
					{Driver: "test-driver", Pool: "pool1", Device: "dev1"},
				}
			},
			verifyErr: func(t *testing.T, err error) {
				if err == nil || !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "Forbidden: changing status.devices requires") {
					t.Errorf("Expected Invalid/Forbidden error, got: %v", err)
				}
			},
		},
		{
			name:        "succeeds with associated-node permission for same-node SA",
			preAllocate: true,
			impersonateExtra: map[string][]string{
				"authentication.kubernetes.io/node-name": {nodeName},
			},
			extraRules: []rbacv1.PolicyRule{{
				APIGroups: []string{"resource.k8s.io"},
				Resources: []string{"resourceclaims/driver"},
				Verbs:     []string{"associated-node:update"},
			}},
			updateClaim: func(c *resourceapi.ResourceClaim) {
				c.Status.Devices = []resourceapi.AllocatedDeviceStatus{
					{Driver: "test-driver", Pool: "pool1", Device: "dev1"},
				}
			},
			verifyErr: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("Expected success via associated-node, got: %v", err)
				}
			},
		},
		{
			name:        "fails deallocation without binding permission",
			preAllocate: true,
			updateClaim: func(c *resourceapi.ResourceClaim) {
				c.Status.Allocation = nil
			},
			verifyErr: func(t *testing.T, err error) {
				if err == nil || !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "Forbidden: changing status.allocation") {
					t.Errorf("Expected Invalid/Forbidden on unbind, got: %v", err)
				}
			},
		},
		{
			name:        "succeeds to update status.reservedFor with binding permission",
			preAllocate: true,
			extraRules: []rbacv1.PolicyRule{{
				APIGroups: []string{"resource.k8s.io"},
				Resources: []string{"resourceclaims/binding"},
				Verbs:     []string{"update"},
			}},
			updateClaim: func(c *resourceapi.ResourceClaim) {
				c.Status.ReservedFor = []resourceapi.ResourceClaimConsumerReference{
					{Resource: "pods", Name: "pod-1", UID: "uid-1"},
				}
			},
			verifyErr: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("Expected success, got: %v", err)
				}
			},
		},
		{
			name:        "fails when updating both allocation and devices but missing binding permission",
			preAllocate: true,
			extraRules: []rbacv1.PolicyRule{{
				// Has driver permission, but LACKS binding permission
				APIGroups: []string{"resource.k8s.io"},
				Resources: []string{"resourceclaims/driver"},
				Verbs:     []string{"arbitrary-node:update"},
			}},
			updateClaim: func(c *resourceapi.ResourceClaim) {
				// Re-allocate to a different node (requires binding)
				if c.Status.Allocation != nil && c.Status.Allocation.NodeSelector != nil {
					c.Status.Allocation.NodeSelector.NodeSelectorTerms[0].MatchFields[0].Values = []string{"worker-2"}
				}
				// Change devices (requires driver)
				c.Status.Devices = []resourceapi.AllocatedDeviceStatus{
					{Driver: "test-driver", Pool: "pool1", Device: "dev2"},
				}
			},
			verifyErr: func(t *testing.T, err error) {
				if err == nil || !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "Forbidden: changing status.allocation") {
					t.Errorf("Expected Forbidden on simultaneous update missing binding, got: %v", err)
				}
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			server := kubeapiservertesting.StartTestServerOrDie(t, nil, []string{
				"--runtime-config=api/all=true",
				"--authorization-mode=RBAC",
			}, framework.SharedEtcd())
			t.Cleanup(server.TearDownFn)

			adminClient := clientset.NewForConfigOrDie(server.ClientConfig)

			// Setup Namespace and Service Account
			_, err := adminClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}

			// Create the base ResourceClaim
			claim := &resourceapi.ResourceClaim{
				ObjectMeta: metav1.ObjectMeta{Name: claimName},
				Spec: resourceapi.ResourceClaimSpec{
					Devices: resourceapi.DeviceClaim{
						Requests: []resourceapi.DeviceRequest{{
							Name: "req-1",
							FirstAvailable: []resourceapi.DeviceSubRequest{{
								Name:            "subreq-1",
								DeviceClassName: "test-class",
							}},
						}},
					},
				},
			}
			_, err = adminClient.ResourceV1().ResourceClaims(ns).Create(ctx, claim, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}

			// Admin Pre-allocation (if required by test)
			if tc.preAllocate {
				c, err := adminClient.ResourceV1().ResourceClaims(ns).Get(ctx, claimName, metav1.GetOptions{})
				if err != nil {
					t.Fatalf("Failed to fetch claim for pre-allocation: %v", err)
				}
				c.Status.Allocation = &resourceapi.AllocationResult{
					NodeSelector: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{nodeName}}},
						}},
					},
					Devices: resourceapi.DeviceAllocationResult{
						Results: []resourceapi.DeviceRequestAllocationResult{
							{Request: "req-1", Driver: "test-driver", Pool: "pool1", Device: "dev1"},
						},
					},
				}
				_, err = adminClient.ResourceV1().ResourceClaims(ns).UpdateStatus(ctx, c, metav1.UpdateOptions{})
				if err != nil {
					t.Fatalf("Admin failed to set baseline allocation: %v", err)
				}
			}

			// Setup RBAC using authutil helpers — these poll via SubjectAccessReview
			// to avoid CI flakes from RBAC propagation delay.
			baseRules := []rbacv1.PolicyRule{
				{APIGroups: []string{"resource.k8s.io"}, Resources: []string{"resourceclaims/status"}, Verbs: []string{"update", "patch"}},
				{APIGroups: []string{"resource.k8s.io"}, Resources: []string{"resourceclaims"}, Verbs: []string{"get"}},
			}
			allRules := append(baseRules, tc.extraRules...)
			for _, rule := range allRules {
				authutil.GrantServiceAccountAuthorization(t, ctx, adminClient, saName, ns, rule)
			}

			// Build the Impersonated Client
			saConfig := rest.CopyConfig(server.ClientConfig)
			saConfig.Impersonate = rest.ImpersonationConfig{
				UserName: fmt.Sprintf("system:serviceaccount:%s:%s", ns, saName),
				Extra:    tc.impersonateExtra,
			}
			saClient := clientset.NewForConfigOrDie(saConfig)

			// Execute Test Update
			cToUpdate, err := adminClient.ResourceV1().ResourceClaims(ns).Get(ctx, claimName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Failed to fetch claim before test execution: %v", err)
			}
			tc.updateClaim(cToUpdate)
			_, testErr := saClient.ResourceV1().ResourceClaims(ns).UpdateStatus(ctx, cToUpdate, metav1.UpdateOptions{})

			// Verify Results
			tc.verifyErr(t, testErr)
		})
	}
}
