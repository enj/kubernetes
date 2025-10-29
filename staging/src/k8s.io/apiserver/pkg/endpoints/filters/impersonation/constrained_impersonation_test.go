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
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"
)

type constrainedImpersonateAuthorizer struct {
	constrainedImpersonationHandler *constrainedImpersonationHandler

	// lock guards below fields
	lock         sync.Mutex
	checkedAttrs []authorizer.Attributes
}

func (c *constrainedImpersonateAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
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

func echoUserInfoHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		u, ok := request.UserFrom(req.Context())
		if !ok {
			t.Fatal("user not found in request")
		}

		_ = json.NewEncoder(w).Encode(&user.DefaultInfo{
			Name:   u.GetName(),
			UID:    u.GetUID(),
			Groups: u.GetGroups(),
			Extra:  u.GetExtra(),
		})

		if _, ok := req.Header[authenticationv1.ImpersonateUserHeader]; ok {
			t.Fatal("user header still present")
		}
		if _, ok := req.Header[authenticationv1.ImpersonateUIDHeader]; ok {
			t.Fatal("uid header still present")
		}
		if _, ok := req.Header[authenticationv1.ImpersonateGroupHeader]; ok {
			t.Fatal("group header still present")
		}
		for key := range req.Header {
			if strings.HasPrefix(key, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
				t.Fatalf("extra header still present: %v", key)
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

func (c *constrainedImpersonateAuthorizer) handler(t *testing.T) http.Handler {
	s := runtime.NewScheme()
	metav1.AddToGroupVersion(s, metav1.SchemeGroupVersion)
	addImpersonation := WithConstrainedImpersonation(echoUserInfoHandler(t), c, serializer.NewCodecFactory(s))
	c.constrainedImpersonationHandler = addImpersonation.(*constrainedImpersonationHandler)

	addAuthentication := authenticationHandler(t, addImpersonation)
	addRequestInfo := requestInfoHandler(t, addAuthentication)
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

func (c *constrainedImpersonateAuthorizer) assertAttributes(t *testing.T, expectedRequest testRequest) {
	c.lock.Lock()
	defer c.lock.Unlock()

	assert.Equal(t, len(expectedRequest.expectedAttributes), len(c.checkedAttrs))
	defer func() { c.checkedAttrs = nil }()

	for i := range c.checkedAttrs {
		want := expectedRequest.expectedAttributes[i]
		got := c.checkedAttrs[i]

		fs, err := got.GetFieldSelector()
		require.NoError(t, err)
		require.Empty(t, fs)
		ls, err := got.GetLabelSelector()
		require.NoError(t, err)
		require.Empty(t, ls)

		assert.Equal(t, want.GetAPIGroup(), got.GetAPIGroup())
		assert.Equal(t, want.GetAPIVersion(), got.GetAPIVersion(), i)
		assert.Equal(t, want.GetResource(), got.GetResource())
		assert.Equal(t, want.GetSubresource(), got.GetSubresource())
		assert.Equal(t, want.GetVerb(), got.GetVerb())
		assert.Equal(t, want.GetName(), got.GetName())
		assert.Equal(t, want.GetNamespace(), got.GetNamespace())
		assert.Equal(t, want.GetPath(), got.GetPath())
		assert.Equal(t, want.IsResourceRequest(), got.IsResourceRequest())
		assertUserInfo(t, expectedRequest.expectedAttributesUser, got.GetUser())
	}
}

func (c *constrainedImpersonateAuthorizer) assertCache(t *testing.T, impersonator, impersonationUser *user.DefaultInfo, expect *expectCache) {
	attrs := authorizer.AttributesRecord{User: impersonator}
	if !expect.modeIndexCached {
		_, exist := c.constrainedImpersonationHandler.tracker.idxCache.get(attrs)
		assert.False(t, exist)
		return
	}
	idx, exist := c.constrainedImpersonationHandler.tracker.idxCache.get(attrs)
	assert.True(t, exist)
	mode := c.constrainedImpersonationHandler.tracker.modes[idx]

	var constrainedMode *constrainedImpersonationModeState
	var associatedNodeCache bool
	switch typedMode := mode.(type) {
	case *constrainedImpersonationModeState:
		constrainedMode = typedMode
	case *associatedNodeImpersonationCheck:
		associatedNodeCache = true
		constrainedMode = typedMode.mode.(*constrainedImpersonationModeState)
	default:
		// legacy impersonate
		return
	}

	if expect.impersonateCached {
		assert.Equal(t, 1, constrainedMode.state.cache.cache.Len())
		assertCacheKey(t, constrainedMode.state.cache, impersonationUser, attrs, associatedNodeCache)
	}

	assert.Equal(t, len(expect.impersonateOnCachedRequests), constrainedMode.cache.cache.Len())
	for _, req := range expect.impersonateOnCachedRequests {
		reqContext := request.WithRequestInfo(request.NewContext(), req)
		reqContext = request.WithUser(reqContext, impersonator)
		attrs, err := filters.GetAuthorizerAttributes(reqContext)
		if err != nil {
			t.Fatal(err)
		}
		assertCacheKey(t, constrainedMode.cache, impersonationUser, attrs, associatedNodeCache)
	}
}

func assertCacheKey(t *testing.T, cache *impersonationCache, impersonationUser *user.DefaultInfo, attrs authorizer.Attributes, associatedNodeCache bool) {
	var key *impersonationCacheKey
	if associatedNodeCache {
		key = &impersonationCacheKey{wantedUser: &user.DefaultInfo{Name: "system:node:*"}, attributes: &associatedNodeImpersonationAttributes{Attributes: attrs}}
	} else {
		key = &impersonationCacheKey{wantedUser: impersonationUser, attributes: attrs}
	}
	info := cache.get(key)
	assert.True(t, info != nil)
}

// clear called after each test case to clear cache
func (c *constrainedImpersonateAuthorizer) clear() {
	c.constrainedImpersonationHandler.tracker.idxCache.cache.Clear()
	for _, mode := range c.constrainedImpersonationHandler.tracker.modes {
		switch typedMode := mode.(type) {
		case *constrainedImpersonationModeState:
			typedMode.cache.cache = cache.NewExpiring()
			typedMode.state.cache.cache = cache.NewExpiring()
		case *associatedNodeImpersonationCheck:
			constrainedMode := typedMode.mode.(*constrainedImpersonationModeState)
			constrainedMode.cache.cache = cache.NewExpiring()
			constrainedMode.state.cache.cache = cache.NewExpiring()
		}
	}
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
	impersonateCached           bool
	impersonateOnCachedRequests []*request.RequestInfo
}

type testRequest struct {
	request                *request.RequestInfo
	expectedAttributesUser *user.DefaultInfo
	expectedUserInfo       *user.DefaultInfo
	expectedAttributes     []authorizer.Attributes
	expectCache            *expectCache
	expectedCode           int
	expectedMessage        string
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
		name              string
		requestor         *user.DefaultInfo
		impersonationUser *user.DefaultInfo
		requests          []testRequest
		expectedUser      user.Info
	}{
		{
			name:         "impersonating-error",
			requestor:    &user.DefaultInfo{Name: "tester"},
			expectedUser: nil,
			requests: []testRequest{
				{
					request: getPodRequest,
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
			impersonationUser: &user.DefaultInfo{Name: "anyone"},
		},
		{
			name:      "impersonating-user-get-allowed-create-disallowed",
			requestor: &user.DefaultInfo{Name: "user-impersonater"},
			expectedUser: &user.DefaultInfo{
				Name:   "anyone",
				Groups: []string{"system:authenticated"},
			},
			requests: []testRequest{
				{
					request: getPodRequest,
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
					request: getAnotherPodRequest,
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
					expectedUserInfo: &user.DefaultInfo{Name: "user-impersonater"},
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
			impersonationUser: &user.DefaultInfo{Name: "anyone"},
		},
		{
			name:      "impersonating-sa-allowed",
			requestor: &user.DefaultInfo{Name: "sa-impersonater"},
			expectedUser: &user.DefaultInfo{
				Name:   "system:serviceaccount:default:default",
				Groups: []string{"system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"},
			},
			requests: []testRequest{
				{
					request: getPodRequest,
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
			impersonationUser: &user.DefaultInfo{Name: "system:serviceaccount:default:default"},
		},
		{
			name:         "impersonating-node-not-allowed",
			requestor:    &user.DefaultInfo{Name: "sa-impersonater"},
			expectedUser: &user.DefaultInfo{Name: "sa-impersonater"},
			requests: []testRequest{
				{
					request: getPodRequest,
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
			impersonationUser: &user.DefaultInfo{Name: "system:node:node1"},
		},
		{
			name:      "impersonating-node-not-allowed-action",
			requestor: &user.DefaultInfo{Name: "node-impersonater"},
			expectedUser: &user.DefaultInfo{
				Name: "node-impersonater",
			},
			requests: []testRequest{
				{
					request: createPodRequest,
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(createPodRequest, "arbitrary-node"),
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:node:node1"}},
					},
					expectCache:     &expectCache{},
					expectedCode:    http.StatusForbidden,
					expectedMessage: `pods "foo" is forbidden: User "node-impersonater" cannot impersonate-on:arbitrary-node:create resource "pods" in API group "" in the namespace "bar": deny by default`,
				},
			},
			impersonationUser: &user.DefaultInfo{Name: "system:node:node1"},
		},
		{
			name:      "impersonating-node-allowed",
			requestor: &user.DefaultInfo{Name: "node-impersonater"},
			expectedUser: &user.DefaultInfo{
				Name:   "system:node:node1",
				Groups: []string{user.NodesGroup, "system:authenticated"},
			},
			impersonationUser: &user.DefaultInfo{Name: "system:node:node1"},
			requests: []testRequest{
				{
					request: getPodRequest,
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
			requestor: &user.DefaultInfo{
				Name:   "user-impersonater",
				Groups: []string{"group-impersonater"},
			},
			expectedUser: &user.DefaultInfo{
				Name:   "user-impersonater",
				Groups: []string{"group-impersonater"},
			},
			impersonationUser: &user.DefaultInfo{
				Name:   "system:admin",
				Groups: []string{"extra-setter-scopes"},
				Extra:  map[string][]string{"scopes": {"scope-a", "scope-b"}},
			},
			requests: []testRequest{
				{
					request: getPodRequest,
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
			requestor: &user.DefaultInfo{
				Name:   "user-impersonater",
				Groups: []string{"extra-setter-scopes"},
			},
			expectedUser: &user.DefaultInfo{
				Name:   "system:admin",
				Groups: []string{"system:authenticated"},
				Extra:  map[string][]string{"scopes": {"scope-a", "scope-b"}},
			},
			requests: []testRequest{
				{
					request: getPodRequest,
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
			impersonationUser: &user.DefaultInfo{
				Name:  "system:admin",
				Extra: map[string][]string{"scopes": {"scope-a", "scope-b"}},
			},
		},
		{
			name: "allowed-associate-node",
			requestor: &user.DefaultInfo{
				Name:   "system:serviceaccount:default:default",
				Groups: []string{"associate-node-impersonater"},
				Extra: map[string][]string{
					serviceaccount.NodeNameKey: {"node1"},
				},
			},
			expectedUser: &user.DefaultInfo{
				Name:   "system:node:node1",
				Groups: []string{user.NodesGroup, "system:authenticated"},
			},
			requests: []testRequest{
				{
					request: getPodRequest,
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
			impersonationUser: &user.DefaultInfo{Name: "system:node:node1"},
		},
		{
			name: "disallowed-associate-node-without-sa",
			requestor: &user.DefaultInfo{
				Name:   "user-impersonater",
				Groups: []string{"associate-node-impersonater"},
				Extra: map[string][]string{
					serviceaccount.NodeNameKey: {"node1"},
				},
			},
			expectedUser: &user.DefaultInfo{
				Name:   "user-impersonater",
				Groups: []string{"associate-node-impersonater"},
				Extra: map[string][]string{
					serviceaccount.NodeNameKey: {"node1"},
				},
			},
			requests: []testRequest{
				{
					request: getPodRequest,
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
			impersonationUser: &user.DefaultInfo{Name: "system:node:node1"},
		},
		{
			name:      "allowed-legacy-impersonator",
			requestor: &user.DefaultInfo{Name: "legacy-impersonater"},
			expectedUser: &user.DefaultInfo{
				Name:   "system:admin",
				Groups: []string{"system:authenticated"},
			},
			requests: []testRequest{
				{
					request: getPodRequest,
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "user-info"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:admin"}, mode: "user-info"},
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:admin"}},
					},
					expectCache:  &expectCache{modeIndexCached: true},
					expectedCode: http.StatusOK,
				},
			},
			impersonationUser: &user.DefaultInfo{Name: "system:admin"},
		},
		{
			name: "continuous-same-allowed-user-requests",
			requestor: &user.DefaultInfo{
				Name: "user-impersonater",
			},
			expectedUser: &user.DefaultInfo{
				Name:   "bob",
				Groups: []string{"system:authenticated"},
			},
			requests: []testRequest{
				{
					request: getDeploymentRequest,
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
					request:      getDeploymentRequest,
					expectedCode: http.StatusOK,
					expectCache: &expectCache{
						modeIndexCached:             true,
						impersonateCached:           true,
						impersonateOnCachedRequests: []*request.RequestInfo{getDeploymentRequest},
					},
				},
			},
			impersonationUser: &user.DefaultInfo{Name: "bob"},
		},
	}

	constrainedAuthorizer := &constrainedImpersonateAuthorizer{}
	server := httptest.NewServer(constrainedAuthorizer.handler(t))
	defer server.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, r := range tc.requests {
				client := &http.Client{
					Transport: &testRoundTripper{
						user:        tc.requestor,
						requestInfo: r.request,
						delegate: transport.NewImpersonatingRoundTripper(
							transport.ImpersonationConfig{
								UserName: tc.impersonationUser.Name,
								UID:      tc.impersonationUser.UID,
								Groups:   tc.impersonationUser.Groups,
								Extra:    tc.impersonationUser.Extra,
							},
							http.DefaultTransport,
						),
					},
				}

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
				if err != nil {
					t.Fatal(err)
				}

				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != r.expectedCode {
					t.Fatalf("%s: expected %v, actual %v", tc.name, r.expectedCode, resp.StatusCode)
				}

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tc.name, err)
					return
				}
				_ = resp.Body.Close()

				if r.expectedCode == http.StatusOK {
					var actualUser user.DefaultInfo
					if err := json.Unmarshal(body, &actualUser); err != nil {
						t.Errorf("unexpected error: %v, body=\n%s", err, string(body))
					}

					expectedUser := tc.expectedUser
					if r.expectedUserInfo != nil {
						expectedUser = r.expectedUserInfo
					}
					assertUserInfo(t, expectedUser, &actualUser)
				} else {
					var status metav1.Status
					if err := json.Unmarshal(body, &status); err != nil {
						t.Errorf("unexpected error: %v, body=\n%s", err, string(body))
					}
					assert.Equal(t, r.expectedMessage, status.Message)
				}

				// set expected users in attributes to impersonator if it is not specifically set.
				if r.expectedAttributesUser == nil {
					r.expectedAttributesUser = tc.requestor
				}

				constrainedAuthorizer.assertAttributes(t, r)
				constrainedAuthorizer.assertCache(t, tc.requestor, tc.impersonationUser, r.expectCache)
			}
			constrainedAuthorizer.clear()
		})
	}
}

func assertUserInfo(t *testing.T, expect, actual user.Info) {
	t.Helper()

	if expect == nil && actual == nil {
		return
	}
	if expect == nil || actual == nil {
		t.Errorf("expected %v, actual %v", expect, actual)
	}
	assert.Equal(t, expect.GetName(), actual.GetName())
	assert.Equal(t, expect.GetUID(), actual.GetUID())
	assert.Equal(t, expect.GetGroups(), actual.GetGroups())
	assert.Equal(t, expect.GetExtra(), actual.GetExtra())
}
