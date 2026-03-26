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

package resource

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/resource"
)

// TestGetModifiedDrivers contains the unit tests for the getModifiedDrivers function.
func TestGetModifiedDrivers(t *testing.T) {
	devStatus := func(driver, pool, device string, network *resource.NetworkDeviceData) resource.AllocatedDeviceStatus {
		return resource.AllocatedDeviceStatus{
			Driver:      driver,
			Pool:        pool,
			Device:      device,
			NetworkData: network,
		}
	}

	claimStatus := func(devices ...resource.AllocatedDeviceStatus) resource.ResourceClaimStatus {
		return resource.ResourceClaimStatus{
			Devices: devices,
		}
	}

	testCases := map[string]struct {
		newStatus resource.ResourceClaimStatus
		oldStatus resource.ResourceClaimStatus
		expected  sets.Set[string]
	}{
		"no changes": {
			newStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", nil),
				devStatus("driver-b", "pool-1", "dev-2", nil),
			),
			oldStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", nil),
				devStatus("driver-b", "pool-1", "dev-2", nil),
			),
			expected: sets.Set[string]{},
		},
		"add one device": {
			newStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", nil),
				devStatus("driver-b", "pool-1", "dev-2", nil),
			),
			oldStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", nil),
			),
			expected: sets.New[string]("driver-b"),
		},
		"add device for existing driver": {
			newStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", nil),
				devStatus("driver-a", "pool-1", "dev-2", nil),
			),
			oldStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", nil),
			),
			expected: sets.New[string]("driver-a"),
		},
		"remove one device": {
			newStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", nil),
			),
			oldStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", nil),
				devStatus("driver-b", "pool-1", "dev-2", nil),
			),
			expected: sets.New[string]("driver-b"),
		},
		"modify one device": {
			newStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", &resource.NetworkDeviceData{InterfaceName: "eth0", IPs: []string{"192.168.7.1/24"}}),
			),
			oldStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", &resource.NetworkDeviceData{InterfaceName: "eth0"}),
			),
			expected: sets.New[string]("driver-a"),
		},
		"complex change (add, remove, modify)": {
			newStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", &resource.NetworkDeviceData{InterfaceName: "eth0", IPs: []string{"192.168.7.1/24"}}),
				devStatus("driver-b", "pool-1", "dev-2", nil),
				devStatus("driver-c", "pool-1", "dev-3", nil),
			),
			oldStatus: claimStatus(
				devStatus("driver-a", "pool-1", "dev-1", &resource.NetworkDeviceData{InterfaceName: "eth0"}),
				devStatus("driver-b", "pool-1", "dev-2", nil),
				devStatus("driver-d", "pool-1", "dev-4", nil),
			),
			expected: sets.New[string]("driver-a", "driver-c", "driver-d"),
		},
		"empty to empty": {
			newStatus: claimStatus(),
			oldStatus: claimStatus(),
			expected:  sets.Set[string]{},
		},
		"empty to one device": {
			newStatus: claimStatus(devStatus("driver-a", "pool-1", "dev-1", nil)),
			oldStatus: claimStatus(),
			expected:  sets.New[string]("driver-a"),
		},
		"one device to empty": {
			newStatus: claimStatus(),
			oldStatus: claimStatus(devStatus("driver-a", "pool-1", "dev-1", nil)),
			expected:  sets.New[string]("driver-a"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result := getModifiedDrivers(tc.newStatus, tc.oldStatus)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// authzCall records the attributes of a single authorization check.
type authzCall struct {
	verb        string
	resource    string
	subresource string
	namespace   string
	name        string
}

func (c authzCall) String() string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", c.verb, c.resource, c.subresource, c.namespace, c.name)
}

// fakeAuthorizer records authorization calls and returns preconfigured decisions.
// Rules are keyed by "verb/resource/subresource/namespace/name".
type fakeAuthorizer struct {
	rules map[string]authorizer.Decision
	err   error // if non-nil, returned alongside the decision for all calls
	calls []authzCall
}

func (f *fakeAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	call := authzCall{
		verb:        a.GetVerb(),
		resource:    a.GetResource(),
		subresource: a.GetSubresource(),
		namespace:   a.GetNamespace(),
		name:        a.GetName(),
	}
	f.calls = append(f.calls, call)

	key := call.String()
	if decision, ok := f.rules[key]; ok {
		return decision, "", f.err
	}
	return authorizer.DecisionDeny, "no rule matched", f.err
}

// withRequestContext builds a context simulating what GetAuthorizerAttributes expects.
func withRequestContext(ctx context.Context, u user.Info, verb string) context.Context {
	ctx = genericapirequest.WithUser(ctx, u)
	ctx = genericapirequest.WithRequestInfo(ctx, &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Verb:              verb,
		APIGroup:          "resource.k8s.io",
		APIVersion:        "v1",
		Resource:          "resourceclaims",
		Subresource:       "status",
		Namespace:         "default",
		Name:              "test-claim",
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, "/", nil)
	return req.Context()
}

func singleNodeAllocation(nodeName string) *resource.AllocationResult {
	return &resource.AllocationResult{
		NodeSelector: &core.NodeSelector{
			NodeSelectorTerms: []core.NodeSelectorTerm{{
				MatchFields: []core.NodeSelectorRequirement{
					{Key: "metadata.name", Operator: core.NodeSelectorOpIn, Values: []string{nodeName}},
				},
			}},
		},
	}
}

func assertErrors(t *testing.T, errs field.ErrorList, expectErrs []string) {
	t.Helper()
	if len(errs) != len(expectErrs) {
		t.Fatalf("expected %d error(s), got %d: %v", len(expectErrs), len(errs), errs)
	}
	for i, expected := range expectErrs {
		if !strings.Contains(errs[i].Error(), expected) {
			t.Errorf("error[%d]: expected substring %q in %q", i, expected, errs[i].Error())
		}
	}
}

func assertCalls(t *testing.T, fa *fakeAuthorizer, expectCalls []authzCall) {
	t.Helper()
	if len(fa.calls) != len(expectCalls) {
		t.Fatalf("expected %d authz call(s), got %d: %v", len(expectCalls), len(fa.calls), fa.calls)
	}
	for i, expected := range expectCalls {
		got := fa.calls[i]
		if got != expected {
			t.Errorf("call[%d]: expected %v, got %v", i, expected, got)
		}
	}
}

func TestAuthorizedForBinding(t *testing.T) {
	saName := "system:serviceaccount:kube-system:scheduler"
	testUser := &user.DefaultInfo{Name: saName}
	fp := field.NewPath("status")

	bindingCall := authzCall{
		verb:        "update",
		resource:    "resourceclaims",
		subresource: "binding",
		namespace:   "", // cluster-wide
		name:        "",
	}

	testcases := []struct {
		name        string
		newStatus   resource.ResourceClaimStatus
		oldStatus   resource.ResourceClaimStatus
		authz       *fakeAuthorizer
		expectErrs  []string
		expectCalls []authzCall
	}{
		{
			name: "no allocation or reservedFor change, no check needed",
			newStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: "d", Pool: "p", Device: "dev"}},
			},
			oldStatus:   resource.ResourceClaimStatus{},
			authz:       &fakeAuthorizer{rules: map[string]authorizer.Decision{}},
			expectCalls: nil, // no authz calls
		},
		{
			name: "allocation changed, authorized",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation("node-1"),
			},
			oldStatus: resource.ResourceClaimStatus{},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				bindingCall.String(): authorizer.DecisionAllow,
			}},
			expectCalls: []authzCall{bindingCall},
		},
		{
			name: "allocation changed, denied",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation("node-1"),
			},
			oldStatus:   resource.ResourceClaimStatus{},
			authz:       &fakeAuthorizer{rules: map[string]authorizer.Decision{}},
			expectErrs:  []string{"changing status.allocation or status.reservedFor requires extra permission"},
			expectCalls: []authzCall{bindingCall},
		},
		{
			name: "reservedFor changed, authorized",
			newStatus: resource.ResourceClaimStatus{
				ReservedFor: []resource.ResourceClaimConsumerReference{{Resource: "pods", Name: "pod-1", UID: "uid-1"}},
			},
			oldStatus: resource.ResourceClaimStatus{},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				bindingCall.String(): authorizer.DecisionAllow,
			}},
			expectCalls: []authzCall{bindingCall},
		},
		{
			name: "reservedFor changed, denied",
			newStatus: resource.ResourceClaimStatus{
				ReservedFor: []resource.ResourceClaimConsumerReference{{Resource: "pods", Name: "pod-1", UID: "uid-1"}},
			},
			oldStatus:   resource.ResourceClaimStatus{},
			authz:       &fakeAuthorizer{rules: map[string]authorizer.Decision{}},
			expectErrs:  []string{"changing status.allocation or status.reservedFor requires extra permission"},
			expectCalls: []authzCall{bindingCall},
		},
		{
			name: "authorizer error but allows",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation("node-1"),
			},
			oldStatus: resource.ResourceClaimStatus{},
			authz: &fakeAuthorizer{
				rules: map[string]authorizer.Decision{bindingCall.String(): authorizer.DecisionAllow},
				err:   fmt.Errorf("transient error"),
			},
			// DecisionAllow wins even with error
			expectCalls: []authzCall{bindingCall},
		},
		{
			name: "authorizer error with deny",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation("node-1"),
			},
			oldStatus: resource.ResourceClaimStatus{},
			authz: &fakeAuthorizer{
				rules: map[string]authorizer.Decision{},
				err:   fmt.Errorf("transient error"),
			},
			expectErrs:  []string{"changing status.allocation or status.reservedFor requires extra permission"},
			expectCalls: []authzCall{bindingCall},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := withRequestContext(context.Background(), testUser, "update")
			errs := AuthorizedForBinding(ctx, fp, tc.authz, tc.newStatus, tc.oldStatus)
			assertErrors(t, errs, tc.expectErrs)
			if tc.expectCalls != nil {
				assertCalls(t, tc.authz, tc.expectCalls)
			}
		})
	}
}

func TestAuthorizedForDeviceStatus(t *testing.T) {
	saName := "system:serviceaccount:kube-system:dra-driver"
	nodeName := "test-node"
	driverName := "test-driver"
	fp := field.NewPath("status", "devices")

	associatedCall := func(verb, driver string) authzCall {
		return authzCall{verb: "associated-node:" + verb, resource: "resourceclaims", subresource: "driver", namespace: "default", name: driver}
	}
	arbitraryCall := func(verb, driver string) authzCall {
		return authzCall{verb: "arbitrary-node:" + verb, resource: "resourceclaims", subresource: "driver", namespace: "default", name: driver}
	}

	testcases := []struct {
		name        string
		newStatus   resource.ResourceClaimStatus
		oldStatus   resource.ResourceClaimStatus
		user        user.Info
		authz       *fakeAuthorizer
		verb        string
		expectErrs  []string
		expectCalls []authzCall
	}{
		{
			name: "no drivers modified",
			newStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "device"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "device"}},
			},
			user:  &user.DefaultInfo{Name: saName},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{}},
			verb:  "update",
		},
		{
			name: "associated-node: allowed by associated-node verb",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName, Extra: map[string][]string{serviceaccount.NodeNameKey: {nodeName}}},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				associatedCall("update", driverName).String(): authorizer.DecisionAllow,
			}},
			verb:        "update",
			expectCalls: []authzCall{associatedCall("update", driverName)},
		},
		{
			name: "associated-node: denied by associated-node, allowed by arbitrary-node fallback",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName, Extra: map[string][]string{serviceaccount.NodeNameKey: {nodeName}}},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				arbitraryCall("update", driverName).String(): authorizer.DecisionAllow,
			}},
			verb: "update",
			// Both verbs tried: associated-node first, then arbitrary-node
			expectCalls: []authzCall{associatedCall("update", driverName), arbitraryCall("update", driverName)},
		},
		{
			name: "associated-node: neither verb allowed",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user:  &user.DefaultInfo{Name: saName, Extra: map[string][]string{serviceaccount.NodeNameKey: {nodeName}}},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{}},
			verb:  "update",
			// Both verbs tried, both denied
			expectErrs:  []string{"changing status.devices requires extra permission"},
			expectCalls: []authzCall{associatedCall("update", driverName), arbitraryCall("update", driverName)},
		},
		{
			name: "SA on different node: only arbitrary-node checked, allowed",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation("other-node"),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName, Extra: map[string][]string{serviceaccount.NodeNameKey: {nodeName}}},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				arbitraryCall("update", driverName).String(): authorizer.DecisionAllow,
			}},
			verb:        "update",
			expectCalls: []authzCall{arbitraryCall("update", driverName)},
		},
		{
			name: "SA on different node: associated-node not checked, denied",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation("other-node"),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName, Extra: map[string][]string{serviceaccount.NodeNameKey: {nodeName}}},
			// Only grant associated-node, which should NOT be checked since nodes differ
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				associatedCall("update", driverName).String(): authorizer.DecisionAllow,
			}},
			verb:        "update",
			expectErrs:  []string{"changing status.devices requires extra permission"},
			expectCalls: []authzCall{arbitraryCall("update", driverName)},
		},
		{
			name: "controller (no node association): allowed by arbitrary-node",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName}, // no node-name extra
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				arbitraryCall("update", driverName).String(): authorizer.DecisionAllow,
			}},
			verb:        "update",
			expectCalls: []authzCall{arbitraryCall("update", driverName)},
		},
		{
			name: "controller (no node association): denied",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user:        &user.DefaultInfo{Name: saName},
			authz:       &fakeAuthorizer{rules: map[string]authorizer.Decision{}},
			verb:        "update",
			expectErrs:  []string{"changing status.devices requires extra permission"},
			expectCalls: []authzCall{arbitraryCall("update", driverName)},
		},
		{
			name: "multi-node claim (no single node in selector): only arbitrary-node",
			newStatus: resource.ResourceClaimStatus{
				Allocation: &resource.AllocationResult{
					NodeSelector: &core.NodeSelector{
						NodeSelectorTerms: []core.NodeSelectorTerm{{
							MatchFields: []core.NodeSelectorRequirement{
								{Key: "metadata.name", Operator: core.NodeSelectorOpIn, Values: []string{"node-a", "node-b"}},
							},
						}},
					},
				},
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName, Extra: map[string][]string{serviceaccount.NodeNameKey: {"node-a"}}},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				arbitraryCall("update", driverName).String(): authorizer.DecisionAllow,
			}},
			verb:        "update",
			expectCalls: []authzCall{arbitraryCall("update", driverName)},
		},
		{
			name: "patch verb propagated to authz check",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName, Extra: map[string][]string{serviceaccount.NodeNameKey: {nodeName}}},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				associatedCall("patch", driverName).String(): authorizer.DecisionAllow,
			}},
			verb:        "patch",
			expectCalls: []authzCall{associatedCall("patch", driverName)},
		},
		{
			name: "multiple drivers: one allowed, one denied",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices: []resource.AllocatedDeviceStatus{
					{Driver: "driver-a", Pool: "pool", Device: "dev-new"},
					{Driver: "driver-b", Pool: "pool", Device: "dev-new"},
				},
			},
			oldStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices: []resource.AllocatedDeviceStatus{
					{Driver: "driver-a", Pool: "pool", Device: "dev-old"},
					{Driver: "driver-b", Pool: "pool", Device: "dev-old"},
				},
			},
			user: &user.DefaultInfo{Name: saName, Extra: map[string][]string{serviceaccount.NodeNameKey: {nodeName}}},
			authz: &fakeAuthorizer{rules: map[string]authorizer.Decision{
				associatedCall("update", "driver-a").String(): authorizer.DecisionAllow,
				// driver-b has no rules → denied
			}},
			verb:       "update",
			expectErrs: []string{"changing status.devices requires extra permission"},
			// driver-a: associated-node allowed on first try
			// driver-b: associated-node denied, arbitrary-node denied
			expectCalls: []authzCall{
				associatedCall("update", "driver-a"),
				associatedCall("update", "driver-b"),
				arbitraryCall("update", "driver-b"),
			},
		},
		{
			name: "authorizer error but allows (decision before error)",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName},
			authz: &fakeAuthorizer{
				rules: map[string]authorizer.Decision{
					arbitraryCall("update", driverName).String(): authorizer.DecisionAllow,
				},
				err: fmt.Errorf("transient error"),
			},
			verb:        "update",
			expectCalls: []authzCall{arbitraryCall("update", driverName)},
		},
		{
			name: "authorizer error with deny",
			newStatus: resource.ResourceClaimStatus{
				Allocation: singleNodeAllocation(nodeName),
				Devices:    []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-new"}},
			},
			oldStatus: resource.ResourceClaimStatus{
				Devices: []resource.AllocatedDeviceStatus{{Driver: driverName, Pool: "pool", Device: "dev-old"}},
			},
			user: &user.DefaultInfo{Name: saName},
			authz: &fakeAuthorizer{
				rules: map[string]authorizer.Decision{},
				err:   fmt.Errorf("transient error"),
			},
			verb:        "update",
			expectErrs:  []string{"changing status.devices requires extra permission"},
			expectCalls: []authzCall{arbitraryCall("update", driverName)},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := withRequestContext(context.Background(), tc.user, tc.verb)
			errs := AuthorizedForDeviceStatus(ctx, fp, tc.authz, tc.newStatus, tc.oldStatus)
			assertErrors(t, errs, tc.expectErrs)
			if tc.expectCalls != nil {
				assertCalls(t, tc.authz, tc.expectCalls)
			}
		})
	}
}

func TestNodeNameFromAllocation(t *testing.T) {
	testCases := []struct {
		name       string
		allocation *resource.AllocationResult
		expected   string
	}{
		{name: "nil allocation", allocation: nil, expected: ""},
		{name: "nil node selector", allocation: &resource.AllocationResult{}, expected: ""},
		{name: "exact single-node match", allocation: singleNodeAllocation("worker-1"), expected: "worker-1"},
		{
			name: "multiple values",
			allocation: &resource.AllocationResult{
				NodeSelector: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{{
					MatchFields: []core.NodeSelectorRequirement{
						{Key: "metadata.name", Operator: core.NodeSelectorOpIn, Values: []string{"node-a", "node-b"}},
					},
				}}},
			},
			expected: "",
		},
		{
			name: "match expressions instead of match fields",
			allocation: &resource.AllocationResult{
				NodeSelector: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{{
					MatchExpressions: []core.NodeSelectorRequirement{
						{Key: "kubernetes.io/hostname", Operator: core.NodeSelectorOpIn, Values: []string{"node-1"}},
					},
				}}},
			},
			expected: "",
		},
		{
			name: "multiple terms",
			allocation: &resource.AllocationResult{
				NodeSelector: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{
					{MatchFields: []core.NodeSelectorRequirement{{Key: "metadata.name", Operator: core.NodeSelectorOpIn, Values: []string{"node-1"}}}},
					{MatchFields: []core.NodeSelectorRequirement{{Key: "metadata.name", Operator: core.NodeSelectorOpIn, Values: []string{"node-2"}}}},
				}},
			},
			expected: "",
		},
		{
			name: "wrong key",
			allocation: &resource.AllocationResult{
				NodeSelector: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{{
					MatchFields: []core.NodeSelectorRequirement{{Key: "metadata.namespace", Operator: core.NodeSelectorOpIn, Values: []string{"node-1"}}},
				}}},
			},
			expected: "",
		},
		{
			name: "wrong operator",
			allocation: &resource.AllocationResult{
				NodeSelector: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{{
					MatchFields: []core.NodeSelectorRequirement{{Key: "metadata.name", Operator: core.NodeSelectorOpNotIn, Values: []string{"node-1"}}},
				}}},
			},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := nodeNameFromAllocation(tc.allocation)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestSAAssociatedWithAllocatedNode(t *testing.T) {
	validSA := &user.DefaultInfo{
		Name:  "system:serviceaccount:default:dra-driver-sa",
		Extra: map[string][]string{serviceaccount.NodeNameKey: {"worker-node-1"}},
	}

	testCases := []struct {
		name              string
		userInfo          user.Info
		allocatedNodeName string
		expected          bool
	}{
		{name: "SA on matching node", userInfo: validSA, allocatedNodeName: "worker-node-1", expected: true},
		{name: "SA on different node", userInfo: validSA, allocatedNodeName: "worker-node-2", expected: false},
		{name: "empty allocated node name", userInfo: validSA, allocatedNodeName: "", expected: false},
		{
			name: "not a service account (kubelet identity)",
			userInfo: &user.DefaultInfo{
				Name:  "system:node:worker-node-1",
				Extra: map[string][]string{serviceaccount.NodeNameKey: {"worker-node-1"}},
			},
			allocatedNodeName: "worker-node-1",
			expected:          false,
		},
		{
			name: "not a service account (regular user)",
			userInfo: &user.DefaultInfo{
				Name:  "jane-doe",
				Extra: map[string][]string{serviceaccount.NodeNameKey: {"worker-node-1"}},
			},
			allocatedNodeName: "worker-node-1",
			expected:          false,
		},
		{
			name:              "service account missing node name extra attribute",
			userInfo:          &user.DefaultInfo{Name: "system:serviceaccount:default:dra-driver-sa", Extra: map[string][]string{}},
			allocatedNodeName: "worker-node-1",
			expected:          false,
		},
		{
			name: "service account with multiple node names in extra attribute",
			userInfo: &user.DefaultInfo{
				Name:  "system:serviceaccount:default:dra-driver-sa",
				Extra: map[string][]string{serviceaccount.NodeNameKey: {"worker-node-1", "worker-node-2"}},
			},
			allocatedNodeName: "worker-node-1",
			expected:          false,
		},
		{
			name: "service account with invalid node name format",
			userInfo: &user.DefaultInfo{
				Name:  "system:serviceaccount:default:dra-driver-sa",
				Extra: map[string][]string{serviceaccount.NodeNameKey: {"invalid_node_name!"}},
			},
			allocatedNodeName: "invalid_node_name!",
			expected:          false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := saAssociatedWithAllocatedNode(tc.userInfo, tc.allocatedNodeName)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}
