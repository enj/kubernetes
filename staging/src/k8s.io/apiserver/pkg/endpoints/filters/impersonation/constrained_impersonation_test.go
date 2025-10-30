/*
Copyright 2025 The Kubernetes Authors.

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

package impersonation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"
)

type constrainedImpersonationTest struct {
	t *testing.T

	constrainedImpersonationHandler *constrainedImpersonationHandler
	checkedAttrs                    []authorizer.Attributes
	echoCalled                      bool
}

func (c *constrainedImpersonationTest) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	c.checkedAttrs = append(c.checkedAttrs, a)

	u := a.GetUser()

	if u.GetName() == "sa-impersonater" && a.GetVerb() == "impersonate:serviceaccount" && a.GetResource() == "serviceaccounts" {
		return authorizer.DecisionAllow, "", nil
	}

	if u.GetName() == "system:serviceaccount:default:node" && a.GetVerb() == "impersonate:arbitrary-node" && a.GetResource() == "nodes" {
		return authorizer.DecisionAllow, "", nil
	}

	if u.GetName() == "node-impersonater" && a.GetVerb() == "impersonate:arbitrary-node" && a.GetResource() == "nodes" {
		return authorizer.DecisionAllow, "", nil
	}

	if len(u.GetGroups()) > 0 && u.GetGroups()[0] == "associate-node-impersonater" && a.GetVerb() == "impersonate:associated-node" && a.GetResource() == "nodes" {
		return authorizer.DecisionAllow, "", nil
	}

	if u.GetName() == "user-impersonater" && a.GetVerb() == "impersonate:user-info" && a.GetResource() == "users" {
		return authorizer.DecisionAllow, "", nil
	}

	if len(u.GetGroups()) > 0 && u.GetGroups()[0] == "group-impersonater" && a.GetVerb() == "impersonate:user-info" && a.GetResource() == "groups" {
		return authorizer.DecisionAllow, "", nil
	}

	if len(u.GetGroups()) > 0 && u.GetGroups()[0] == "extra-setter-scopes" && a.GetVerb() == "impersonate:user-info" && a.GetResource() == "userextras" && a.GetSubresource() == "scopes" {
		return authorizer.DecisionAllow, "", nil
	}

	if u.GetName() == "legacy-impersonater" && a.GetVerb() == "impersonate" {
		return authorizer.DecisionAllow, "", nil
	}

	if u.GetName() != "legacy-impersonator" &&
		strings.HasPrefix(a.GetVerb(), "impersonate-on:") &&
		(strings.HasSuffix(a.GetVerb(), "list") || strings.HasSuffix(a.GetVerb(), "get")) {
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionNoOpinion, "deny by default", nil
}

func (c *constrainedImpersonationTest) echoUserInfoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		c.echoCalled = true

		u, ok := request.UserFrom(req.Context())
		if !ok {
			c.t.Fatal("user not found in request")
		}

		_ = json.NewEncoder(w).Encode(&user.DefaultInfo{
			Name:   u.GetName(),
			UID:    u.GetUID(),
			Groups: u.GetGroups(),
			Extra:  u.GetExtra(),
		})

		if _, ok := req.Header[authenticationv1.ImpersonateUserHeader]; ok {
			c.t.Fatal("user header still present")
		}
		if _, ok := req.Header[authenticationv1.ImpersonateUIDHeader]; ok {
			c.t.Fatal("uid header still present")
		}
		if _, ok := req.Header[authenticationv1.ImpersonateGroupHeader]; ok {
			c.t.Fatal("group header still present")
		}
		for key := range req.Header {
			if strings.HasPrefix(key, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
				c.t.Fatalf("extra header still present: %v", key)
			}
		}
	}
}

func authenticationHandler(t *testing.T, handler http.Handler) http.Handler {
	return filters.WithAuthentication(handler, authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		userData := req.Header.Get(testUserHeader)
		if len(userData) == 0 {
			t.Fatal("missing user header")
		}
		var u user.DefaultInfo
		if err := json.Unmarshal([]byte(userData), &u); err != nil {
			t.Fatal(err)
		}
		return &authenticator.Response{User: &u}, true, nil
	}), nil, nil, nil)
}

func requestInfoHandler(t *testing.T, handler http.Handler) http.Handler {
	return filters.WithRequestInfo(handler, requestInfoFunc(func(req *http.Request) (*request.RequestInfo, error) {
		requestInfoData := req.Header.Get(testRequestInfoHeader)
		if len(requestInfoData) == 0 {
			t.Fatal("missing request info header")
		}
		var r request.RequestInfo
		if err := json.Unmarshal([]byte(requestInfoData), &r); err != nil {
			t.Fatal(err)
		}
		return &r, nil
	}))
}

const (
	testUserHeader        = "insecure-test-user-json"
	testRequestInfoHeader = "insecure-test-request-info-json"
)

func (c *constrainedImpersonationTest) handler() http.Handler {
	s := runtime.NewScheme()
	metav1.AddToGroupVersion(s, metav1.SchemeGroupVersion)
	addImpersonation := WithConstrainedImpersonation(c.echoUserInfoHandler(), c, serializer.NewCodecFactory(s))
	c.constrainedImpersonationHandler = addImpersonation.(*constrainedImpersonationHandler)

	addAuthentication := authenticationHandler(c.t, addImpersonation)
	addRequestInfo := requestInfoHandler(c.t, addAuthentication)
	return addRequestInfo
}

type requestInfoFunc func(*http.Request) (*request.RequestInfo, error)

func (f requestInfoFunc) NewRequestInfo(req *http.Request) (*request.RequestInfo, error) {
	return f(req)
}

type testRoundTripper struct {
	user        *user.DefaultInfo
	requestInfo *request.RequestInfo
	delegate    http.RoundTripper
}

func (t *testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	userData, err := json.Marshal(t.user)
	if err != nil {
		return nil, err
	}
	requestInfoData, err := json.Marshal(t.requestInfo)
	if err != nil {
		return nil, err
	}
	r.Header.Set(testUserHeader, string(userData))
	r.Header.Set(testRequestInfoHeader, string(requestInfoData))
	return t.delegate.RoundTrip(r)
}

func (c *constrainedImpersonationTest) assertAttributes(expectedRequest testRequest) {
	checkedAttrs := c.checkedAttrs
	c.checkedAttrs = nil

	require.Equal(c.t, len(expectedRequest.expectedAttributes), len(checkedAttrs))

	for i := range checkedAttrs {
		want := &addUserAttributes{Attributes: expectedRequest.expectedAttributes[i], user: expectedRequest.expectedAttributesUser}
		require.Equal(c.t, comparableAttributes(want), comparableAttributes(checkedAttrs[i]))
	}
}

type addUserAttributes struct {
	authorizer.Attributes
	user *user.DefaultInfo
}

func (a *addUserAttributes) GetUser() user.Info {
	return a.user
}

func comparableAttributes(attributes authorizer.Attributes) authorizer.AttributesRecord {
	fs, errFS := attributes.GetFieldSelector()
	ls, errLS := attributes.GetLabelSelector()
	return authorizer.AttributesRecord{
		User:                      comparableUser(attributes.GetUser()),
		Verb:                      attributes.GetVerb(),
		Namespace:                 attributes.GetNamespace(),
		APIGroup:                  attributes.GetAPIGroup(),
		APIVersion:                attributes.GetAPIVersion(),
		Resource:                  attributes.GetResource(),
		Subresource:               attributes.GetSubresource(),
		Name:                      attributes.GetName(),
		ResourceRequest:           attributes.IsResourceRequest(),
		Path:                      attributes.GetPath(),
		FieldSelectorRequirements: fs,
		FieldSelectorParsingErr:   errFS,
		LabelSelectorRequirements: ls,
		LabelSelectorParsingErr:   errLS,
	}
}

func (c *constrainedImpersonationTest) assertEchoCalled(expectedCalled bool) {
	called := c.echoCalled
	c.echoCalled = false
	require.Equal(c.t, expectedCalled, called)
}

func (c *constrainedImpersonationTest) assertCache(requestor, impersonatedUser *user.DefaultInfo, expect *expectCache) {
	attrs := authorizer.AttributesRecord{User: requestor}
	idx, exist := c.constrainedImpersonationHandler.tracker.idxCache.get(attrs)
	if !expect.modeIndexCached {
		require.False(c.t, exist)
		return
	}

	require.True(c.t, exist)
	mode := c.constrainedImpersonationHandler.tracker.modes[idx]

	var constrainedMode *constrainedImpersonationModeState
	var associatedNodeCache bool
	switch typedMode := mode.(type) {
	case *constrainedImpersonationModeState:
		constrainedMode = typedMode
	case *associatedNodeImpersonationCheck:
		associatedNodeCache = true
		constrainedMode = typedMode.mode.(*constrainedImpersonationModeState)
	case *legacyImpersonationCheck:
		require.Equal(c.t, 0, typedMode.m.cache.cache.Len())
		return
	default:
		c.t.Fatalf("unexpected mode: %T", typedMode)
	}

	require.Equal(c.t, len(expect.impersonateOnCachedRequests), constrainedMode.cache.cache.Len())
	for _, req := range expect.impersonateOnCachedRequests {
		reqContext := request.WithRequestInfo(context.Background(), req)
		reqContext = request.WithUser(reqContext, requestor)
		attrs, err := filters.GetAuthorizerAttributes(reqContext)
		if err != nil {
			c.t.Fatal(err)
		}
		assertCacheKey(c.t, constrainedMode.cache, impersonatedUser, attrs, associatedNodeCache)
	}

	if expect.impersonateCached {
		require.Equal(c.t, 1, constrainedMode.state.cache.cache.Len())
		assertCacheKey(c.t, constrainedMode.state.cache, impersonatedUser, attrs, associatedNodeCache)
	} else {
		require.Equal(c.t, 0, constrainedMode.state.cache.cache.Len())
	}
}

func assertCacheKey(t *testing.T, cache *impersonationCache, impersonatedUser *user.DefaultInfo, attrs authorizer.Attributes, associatedNodeCache bool) {
	var key *impersonationCacheKey
	if associatedNodeCache {
		key = &impersonationCacheKey{wantedUser: &user.DefaultInfo{Name: "system:node:*"}, attributes: &associatedNodeImpersonationAttributes{Attributes: attrs}}
	} else {
		key = &impersonationCacheKey{wantedUser: impersonatedUser, attributes: attrs}
	}
	info := cache.get(key)
	require.True(t, info != nil)
}

type impersonateAttrs struct {
	authorizer.AttributesRecord
	mode string
}

func (i *impersonateAttrs) IsResourceRequest() bool {
	return true
}

func (i *impersonateAttrs) GetVerb() string {
	return "impersonate:" + i.mode
}

func (i *impersonateAttrs) GetAPIGroup() string {
	return authenticationv1.SchemeGroupVersion.Group
}

func (i *impersonateAttrs) GetAPIVersion() string {
	return authenticationv1.SchemeGroupVersion.Version
}

func newImpersonateOnAttrs(requestInfo *request.RequestInfo, mode string) *impersonateOnAttributes {
	requestCtx := request.WithRequestInfo(context.Background(), requestInfo)
	attrs, err := filters.GetAuthorizerAttributes(requestCtx)
	if err != nil {
		panic(err)
	}
	return &impersonateOnAttributes{Attributes: attrs, mode: mode}
}

type legacyImpersonateAttrs struct {
	authorizer.AttributesRecord
}

func (l *legacyImpersonateAttrs) GetVerb() string {
	return "impersonate"
}

func (l *legacyImpersonateAttrs) GetAPIVersion() string {
	return "v1"
}

func (l *legacyImpersonateAttrs) IsResourceRequest() bool {
	return true
}

type expectCache struct {
	modeIndexCached             bool
	impersonateOnCachedRequests []*request.RequestInfo
	impersonateCached           bool
}

type expectedCache struct {
	modeIdx map[string]string            // username -> mode verb
	modes   map[string]expectedModeCache // mode verb -> cache
}

type expectedModeCache struct {
	outer map[impersonationCacheKey]*user.DefaultInfo
	inner map[*user.DefaultInfo]*user.DefaultInfo
}

type testRequest struct {
	request          *request.RequestInfo
	requestor        *user.DefaultInfo
	impersonatedUser *user.DefaultInfo

	expectedImpersonatedUser *user.DefaultInfo
	expectedMessage          string

	expectedAttributesUser *user.DefaultInfo // nil means use requestor
	expectedAttributes     []authorizer.Attributes
	expectCache            *expectCache
	expectedCode           int
}

func TestConstrainedImpersonationFilter(t *testing.T) {
	getPodRequest := &request.RequestInfo{
		IsResourceRequest: true,
		Verb:              "get",
		APIVersion:        "v1",
		Resource:          "pods",
		Name:              "foo",
		Namespace:         "bar",
	}

	getAnotherPodRequest := &request.RequestInfo{
		IsResourceRequest: true,
		Verb:              "get",
		APIVersion:        "v1",
		Resource:          "pods",
		Name:              "foo1",
		Namespace:         "bar1",
	}

	createPodRequest := &request.RequestInfo{
		IsResourceRequest: true,
		Verb:              "create",
		APIVersion:        "v1",
		Resource:          "pods",
		Name:              "foo",
		Namespace:         "bar",
	}

	getDeploymentRequest := &request.RequestInfo{
		IsResourceRequest: true,
		Verb:              "get",
		APIVersion:        "v1",
		APIGroup:          "apps",
		Resource:          "deployments",
		Name:              "foo",
		Namespace:         "bar",
	}

	testCases := []struct {
		name     string
		requests []testRequest
	}{
		{
			name: "impersonating-error",
			requests: []testRequest{
				{
					request:          getPodRequest,
					requestor:        &user.DefaultInfo{Name: "tester"},
					impersonatedUser: &user.DefaultInfo{Name: "anyone"},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "user-info"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "anyone"}, mode: "user-info"},
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "anyone"}},
					},
					expectCache:     &expectCache{},
					expectedCode:    http.StatusForbidden,
					expectedMessage: `users.authentication.k8s.io "anyone" is forbidden: User "tester" cannot impersonate:user-info resource "users" in API group "authentication.k8s.io" at the cluster scope: deny by default`,
				},
			},
		},
		{
			name: "impersonating-user-get-allowed-create-disallowed",
			requests: []testRequest{
				{
					request:          getPodRequest,
					requestor:        &user.DefaultInfo{Name: "user-impersonater"},
					impersonatedUser: &user.DefaultInfo{Name: "anyone"},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "anyone",
						Groups: []string{"system:authenticated"},
					},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "user-info"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "anyone"}, mode: "user-info"},
					},
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getPodRequest},
					},
					expectedCode: http.StatusOK,
				},
				{
					request:          getAnotherPodRequest,
					requestor:        &user.DefaultInfo{Name: "user-impersonater"},
					impersonatedUser: &user.DefaultInfo{Name: "anyone"},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "anyone",
						Groups: []string{"system:authenticated"},
					},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getAnotherPodRequest, "user-info"),
					},
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getPodRequest, getAnotherPodRequest},
					},
					expectedCode: http.StatusOK,
				},
				{
					request:          createPodRequest,
					requestor:        &user.DefaultInfo{Name: "user-impersonater"},
					impersonatedUser: &user.DefaultInfo{Name: "anyone"},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(createPodRequest, "user-info"),
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "anyone"}},
					},
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getPodRequest, getAnotherPodRequest},
					},
					expectedCode:    http.StatusForbidden,
					expectedMessage: `pods "foo" is forbidden: User "user-impersonater" cannot impersonate-on:user-info:create resource "pods" in API group "" in the namespace "bar": deny by default`,
				},
			},
		},
		{
			name: "impersonating-sa-allowed",
			requests: []testRequest{
				{
					request:          getPodRequest,
					requestor:        &user.DefaultInfo{Name: "sa-impersonater"},
					impersonatedUser: &user.DefaultInfo{Name: "system:serviceaccount:default:default"},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "system:serviceaccount:default:default",
						Groups: []string{"system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"},
					},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "serviceaccount"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "serviceaccounts", Namespace: "default", Name: "default"}, mode: "serviceaccount"},
					},
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getPodRequest},
					},
					expectedCode: http.StatusOK,
				},
			},
		},
		{
			name: "impersonating-node-not-allowed",
			requests: []testRequest{
				{
					request:          getPodRequest,
					requestor:        &user.DefaultInfo{Name: "sa-impersonater"},
					impersonatedUser: &user.DefaultInfo{Name: "system:node:node1"},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "arbitrary-node"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "nodes", Name: "node1"}, mode: "arbitrary-node"},
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:node:node1"}},
					},
					expectCache:     &expectCache{},
					expectedCode:    http.StatusForbidden,
					expectedMessage: `nodes.authentication.k8s.io "node1" is forbidden: User "sa-impersonater" cannot impersonate:arbitrary-node resource "nodes" in API group "authentication.k8s.io" at the cluster scope: deny by default`,
				},
			},
		},
		{
			name: "impersonating-node-not-allowed-action",
			requests: []testRequest{
				{
					request:          createPodRequest,
					requestor:        &user.DefaultInfo{Name: "node-impersonater"},
					impersonatedUser: &user.DefaultInfo{Name: "system:node:node1"},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(createPodRequest, "arbitrary-node"),
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:node:node1"}},
					},
					expectCache:     &expectCache{},
					expectedCode:    http.StatusForbidden,
					expectedMessage: `pods "foo" is forbidden: User "node-impersonater" cannot impersonate-on:arbitrary-node:create resource "pods" in API group "" in the namespace "bar": deny by default`,
				},
			},
		},
		{
			name: "impersonating-node-allowed",
			requests: []testRequest{
				{
					request:          getPodRequest,
					requestor:        &user.DefaultInfo{Name: "node-impersonater"},
					impersonatedUser: &user.DefaultInfo{Name: "system:node:node1"},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "system:node:node1",
						Groups: []string{user.NodesGroup, "system:authenticated"},
					},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "arbitrary-node"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "nodes", Name: "node1"}, mode: "arbitrary-node"},
					},
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getPodRequest},
					},
					expectedCode: http.StatusOK,
				},
			},
		},
		{
			name: "disallowed-userextra-3",
			requests: []testRequest{
				{
					request: getPodRequest,
					requestor: &user.DefaultInfo{
						Name:   "user-impersonater",
						Groups: []string{"group-impersonater"},
					},
					impersonatedUser: &user.DefaultInfo{
						Name:   "system:admin",
						Groups: []string{"extra-setter-scopes"},
						Extra:  map[string][]string{"scopes": {"scope-a", "scope-b"}},
					},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "user-info"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:admin"}, mode: "user-info"},
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "groups", Name: "extra-setter-scopes"}, mode: "user-info"},
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "userextras", Subresource: "scopes", Name: "scope-a"}, mode: "user-info"},
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:admin"}},
					},
					expectCache:     &expectCache{},
					expectedCode:    http.StatusForbidden,
					expectedMessage: `userextras.authentication.k8s.io "scope-a" is forbidden: User "user-impersonater" cannot impersonate:user-info resource "userextras/scopes" in API group "authentication.k8s.io" at the cluster scope: deny by default`,
				},
			},
		},
		{
			name: "allowed-userextras",
			requests: []testRequest{
				{
					request: getPodRequest,
					requestor: &user.DefaultInfo{
						Name:   "user-impersonater",
						Groups: []string{"extra-setter-scopes"},
					},
					impersonatedUser: &user.DefaultInfo{
						Name:  "system:admin",
						Extra: map[string][]string{"scopes": {"scope-a", "scope-b"}},
					},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "system:admin",
						Groups: []string{"system:authenticated"},
						Extra:  map[string][]string{"scopes": {"scope-a", "scope-b"}},
					},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "user-info"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:admin"}, mode: "user-info"},
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "userextras", Subresource: "scopes", Name: "scope-a"}, mode: "user-info"},
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "userextras", Subresource: "scopes", Name: "scope-b"}, mode: "user-info"},
					},
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getPodRequest},
					},
					expectedCode: http.StatusOK,
				},
			},
		},
		{
			name: "allowed-associate-node",
			requests: []testRequest{
				{
					request: getPodRequest,
					requestor: &user.DefaultInfo{
						Name:   "system:serviceaccount:default:default",
						Groups: []string{"associate-node-impersonater"},
						Extra: map[string][]string{
							serviceaccount.NodeNameKey: {"node1"},
						},
					},
					impersonatedUser: &user.DefaultInfo{Name: "system:node:node1"},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "system:node:node1",
						Groups: []string{user.NodesGroup, "system:authenticated"},
					},
					expectedAttributesUser: &user.DefaultInfo{
						Name:   "system:serviceaccount:default:default",
						Groups: []string{"associate-node-impersonater"},
						Extra: map[string][]string{
							"authentication.kubernetes.io/associated-node-keys": {"authentication.kubernetes.io/node-name"},
						}},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "associated-node"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "nodes", Name: "*"}, mode: "associated-node"},
					},
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getPodRequest},
					},
					expectedCode: http.StatusOK,
				},
			},
		},
		{
			name: "disallowed-associate-node-without-sa",
			requests: []testRequest{
				{
					request: getPodRequest,
					requestor: &user.DefaultInfo{
						Name:   "user-impersonater",
						Groups: []string{"associate-node-impersonater"},
						Extra: map[string][]string{
							serviceaccount.NodeNameKey: {"node1"},
						},
					},
					impersonatedUser: &user.DefaultInfo{Name: "system:node:node1"},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "arbitrary-node"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "nodes", Name: "node1"}, mode: "arbitrary-node"},
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:node:node1"}},
					},
					expectCache:     &expectCache{},
					expectedCode:    http.StatusForbidden,
					expectedMessage: `nodes.authentication.k8s.io "node1" is forbidden: User "user-impersonater" cannot impersonate:arbitrary-node resource "nodes" in API group "authentication.k8s.io" at the cluster scope: deny by default`,
				},
			},
		},
		{
			name: "allowed-legacy-impersonator",
			requests: []testRequest{
				{
					request:          getPodRequest,
					requestor:        &user.DefaultInfo{Name: "legacy-impersonater"},
					impersonatedUser: &user.DefaultInfo{Name: "system:admin"},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "system:admin",
						Groups: []string{"system:authenticated"},
					},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "user-info"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:admin"}, mode: "user-info"},
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:admin"}},
					},
					expectCache:  &expectCache{modeIndexCached: true},
					expectedCode: http.StatusOK,
				},
			},
		},
		{
			name: "continuous-same-allowed-user-requests",
			requests: []testRequest{
				{
					request: getDeploymentRequest,
					requestor: &user.DefaultInfo{
						Name: "user-impersonater",
					},
					impersonatedUser: &user.DefaultInfo{Name: "bob"},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{"system:authenticated"},
					},
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getDeploymentRequest, "user-info"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "bob"}, mode: "user-info"},
					},
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getDeploymentRequest},
					},
					expectedCode: http.StatusOK,
				},
				{
					request: getDeploymentRequest,
					requestor: &user.DefaultInfo{
						Name: "user-impersonater",
					},
					impersonatedUser: &user.DefaultInfo{Name: "bob"},
					expectedImpersonatedUser: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{"system:authenticated"},
					},
					expectedCode: http.StatusOK,
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getDeploymentRequest},
					},
				},
			},
		},
	}

	var mux http.ServeMux
	tests := make([]*constrainedImpersonationTest, len(testCases))
	handlers := make([]http.Handler, len(testCases))
	for i := range len(testCases) {
		mux.Handle("/"+strconv.Itoa(i), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			handlers[i].ServeHTTP(w, req)
		}))
	}

	server := httptest.NewServer(&mux)
	t.Cleanup(server.Close)

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			test := &constrainedImpersonationTest{t: t}
			tests[i] = test
			handlers[i] = test.handler()

			for _, r := range tc.requests {
				client := &http.Client{
					Transport: &testRoundTripper{
						user:        r.requestor,
						requestInfo: r.request,
						delegate: transport.NewImpersonatingRoundTripper(
							transport.ImpersonationConfig{
								UserName: r.impersonatedUser.Name,
								UID:      r.impersonatedUser.UID,
								Groups:   r.impersonatedUser.Groups,
								Extra:    r.impersonatedUser.Extra,
							},
							http.DefaultTransport,
						),
					},
				}

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/"+strconv.Itoa(i), nil)
				if err != nil {
					t.Fatal(err)
				}

				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != r.expectedCode {
					t.Fatalf("expected %v, actual %v", r.expectedCode, resp.StatusCode)
				}

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()

				if r.expectedCode == http.StatusOK {
					var actualUser user.DefaultInfo
					if err := json.Unmarshal(body, &actualUser); err != nil {
						t.Errorf("unexpected error: %v, body=\n%s", err, string(body))
					}

					requireUserInfo(t, r.expectedImpersonatedUser, &actualUser)
					test.assertEchoCalled(true)
					require.NotNil(t, r.expectedImpersonatedUser) // sanity check test data
					require.Empty(t, r.expectedMessage)           // sanity check test data
				} else {
					var status metav1.Status
					if err := json.Unmarshal(body, &status); err != nil {
						t.Errorf("unexpected error: %v, body=\n%s", err, string(body))
					}
					require.Equal(t, r.expectedMessage, status.Message)
					test.assertEchoCalled(false)
					require.NotEmpty(t, r.expectedMessage)     // sanity check test data
					require.Nil(t, r.expectedImpersonatedUser) // sanity check test data
				}

				// set expected users in attributes to impersonator if it is not specifically set.
				if r.expectedAttributesUser == nil {
					r.expectedAttributesUser = r.requestor
				}

				test.assertAttributes(r)
				test.assertCache(r.requestor, r.impersonatedUser, r.expectCache)
			}
		})
	}
}

func requireUserInfo(t *testing.T, expect *user.DefaultInfo, actual user.Info) {
	t.Helper()

	require.Equal(t, expect, comparableUser(actual))
}

func comparableUser(u user.Info) *user.DefaultInfo {
	return &user.DefaultInfo{
		Name:   u.GetName(),
		UID:    u.GetUID(),
		Groups: u.GetGroups(),
		Extra:  u.GetExtra(),
	}
}
