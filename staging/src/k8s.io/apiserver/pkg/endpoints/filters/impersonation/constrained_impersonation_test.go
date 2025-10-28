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
	"k8s.io/apiserver/pkg/endpoints/filters"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	authenticationapi "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

type constrainedImpersonateAuthorizer struct {
	handler *constrainedImpersonationHandler

	checkedAttrs []authorizer.Attributes
	actualUser   user.Info
	requestCtx   context.Context

	lock sync.Mutex
}

func (c *constrainedImpersonateAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.checkedAttrs = append(c.checkedAttrs, a)

	user := a.GetUser()

	if user.GetName() == "sa-impersonater" && a.GetVerb() == "impersonate:serviceaccount" && a.GetResource() == "serviceaccounts" {
		return authorizer.DecisionAllow, "", nil
	}

	if user.GetName() == "system:serviceaccount:default:node" && a.GetVerb() == "impersonate:arbitrary-node" && a.GetResource() == "nodes" {
		return authorizer.DecisionAllow, "", nil
	}

	if user.GetName() == "node-impersonater" && a.GetVerb() == "impersonate:arbitrary-node" && a.GetResource() == "nodes" {
		return authorizer.DecisionAllow, "", nil
	}

	if len(user.GetGroups()) > 0 && user.GetGroups()[0] == "associate-node-impersonater" && a.GetVerb() == "impersonate:associated-node" && a.GetResource() == "nodes" {
		return authorizer.DecisionAllow, "", nil
	}

	if user.GetName() == "user-impersonater" && a.GetVerb() == "impersonate:user-info" && a.GetResource() == "users" {
		return authorizer.DecisionAllow, "", nil
	}

	if len(user.GetGroups()) > 0 && user.GetGroups()[0] == "group-impersonater" && a.GetVerb() == "impersonate:user-info" && a.GetResource() == "groups" {
		return authorizer.DecisionAllow, "", nil
	}

	if len(user.GetGroups()) > 0 && user.GetGroups()[0] == "extra-setter-scopes" && a.GetVerb() == "impersonate:user-info" && a.GetResource() == "userextras" && a.GetSubresource() == "scopes" {
		return authorizer.DecisionAllow, "", nil
	}

	if user.GetName() == "legacy-impersonater" && a.GetVerb() == "impersonate" {
		return authorizer.DecisionAllow, "", nil
	}

	if user.GetName() != "legacy-impersonator" &&
		strings.HasPrefix(a.GetVerb(), "impersonate-on:") &&
		(strings.HasSuffix(a.GetVerb(), "list") || strings.HasSuffix(a.GetVerb(), "get")) {
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionNoOpinion, "deny by default", nil
}

func (c *constrainedImpersonateAuthorizer) finalHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		currentCtx := req.Context()
		user, exists := request.UserFrom(currentCtx)
		if !exists {
			c.actualUser = nil
			return
		}

		c.actualUser = user

		if _, ok := req.Header[authenticationapi.ImpersonateUserHeader]; ok {
			t.Fatal("user header still present")
		}
		if _, ok := req.Header[authenticationapi.ImpersonateGroupHeader]; ok {
			t.Fatal("group header still present")
		}
		for key := range req.Header {
			if strings.HasPrefix(key, authenticationapi.ImpersonateUserExtraHeaderPrefix) {
				t.Fatalf("extra header still present: %v", key)
			}
		}
		if _, ok := req.Header[authenticationapi.ImpersonateUIDHeader]; ok {
			t.Fatal("uid header still present")
		}
	}
}

func (c *constrainedImpersonateAuthorizer) authorizeHandler(t *testing.T) http.HandlerFunc {
	authorizationHandler := WithConstrainedImpersonation(c.finalHandler(t), c, serializer.NewCodecFactory(runtime.NewScheme()))
	c.handler = authorizationHandler.(*constrainedImpersonationHandler)
	return func(w http.ResponseWriter, req *http.Request) {
		req = req.WithContext(c.requestCtx)
		user, exists := request.UserFrom(c.requestCtx)
		if !exists {
			c.actualUser = nil
			return
		} else {
			c.actualUser = user
		}
		authorizationHandler.ServeHTTP(w, req)
	}
}

func (c *constrainedImpersonateAuthorizer) withRequestContext(ctx context.Context) {
	c.requestCtx = ctx
}

func (c *constrainedImpersonateAuthorizer) assertAttributes(t *testing.T, expectedRequest testRequest) {
	c.lock.Lock()
	defer c.lock.Unlock()

	assert.Equal(t, len(expectedRequest.expectedAttributes), len(c.checkedAttrs))
	defer func() { c.checkedAttrs = []authorizer.Attributes{} }()

	for i := range c.checkedAttrs {
		assert.Equal(t, expectedRequest.expectedAttributes[i].GetAPIGroup(), c.checkedAttrs[i].GetAPIGroup())
		assert.Equal(t, expectedRequest.expectedAttributes[i].GetResource(), c.checkedAttrs[i].GetResource())
		assert.Equal(t, expectedRequest.expectedAttributes[i].GetSubresource(), c.checkedAttrs[i].GetSubresource())
		assert.Equal(t, expectedRequest.expectedAttributes[i].GetVerb(), c.checkedAttrs[i].GetVerb())
		assert.Equal(t, expectedRequest.expectedAttributes[i].GetName(), c.checkedAttrs[i].GetName())
		assert.Equal(t, expectedRequest.expectedAttributes[i].GetNamespace(), c.checkedAttrs[i].GetNamespace())
		assert.Equal(t, expectedRequest.expectedAttributes[i].GetPath(), c.checkedAttrs[i].GetPath())
		assert.Equal(t, expectedRequest.expectedAttributes[i].IsResourceRequest(), c.checkedAttrs[i].IsResourceRequest())
		assertUserInfo(t, expectedRequest.expectedAttributesUser, c.checkedAttrs[i].GetUser())
	}
}

func (c *constrainedImpersonateAuthorizer) assertCache(t *testing.T, impersonator, impersonationUser *user.DefaultInfo, expect *expectCache) {
	attrs := authorizer.AttributesRecord{User: impersonator}
	if !expect.modeIndexCached {
		_, exist := c.handler.tracker.idxCache.get(attrs)
		assert.False(t, exist)
		return
	}
	idx, exist := c.handler.tracker.idxCache.get(attrs)
	assert.True(t, exist)
	mode := c.handler.tracker.modes[idx]

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
	c.handler.tracker.idxCache.cache.Clear()
	for _, mode := range c.handler.tracker.modes {
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
	return authenticationapi.SchemeGroupVersion.Group
}

func (i *impersonateAttrs) GetAPIVersion() string {
	return authenticationapi.SchemeGroupVersion.Version
}

type impersonateOnAttrs struct {
	impersonateOnAttributes
}

func newImpersonateOnAttrs(requestInfo *request.RequestInfo, mode string) *impersonateOnAttrs {
	requestCtx := request.WithRequestInfo(request.NewContext(), requestInfo)
	attrs, _ := filters.GetAuthorizerAttributes(requestCtx)
	return &impersonateOnAttrs{
		impersonateOnAttributes: impersonateOnAttributes{Attributes: attrs, mode: mode},
	}
}

type legacyImpersonateAttrs struct {
	authorizer.AttributesRecord
}

func (l *legacyImpersonateAttrs) GetVerb() string {
	return "impersonate"
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
		impersonator      *user.DefaultInfo
		impersonationUser *user.DefaultInfo
		requests          []testRequest
		expectedUser      user.Info
	}{
		{
			name:         "impersonating-error",
			impersonator: &user.DefaultInfo{Name: "tester"},
			expectedUser: &user.DefaultInfo{Name: "tester"},
			requests: []testRequest{
				{
					request: getPodRequest,
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "user-info"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "anyone"}, mode: "user-info"},
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "anyone"}},
					},
					expectCache:  &expectCache{},
					expectedCode: http.StatusForbidden,
				},
			},
			impersonationUser: &user.DefaultInfo{Name: "anyone"},
		},
		{
			name:         "impersonating-user-get-allowed-create-disallowed",
			impersonator: &user.DefaultInfo{Name: "user-impersonater"},
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
					expectedCode: http.StatusForbidden,
				},
			},
			impersonationUser: &user.DefaultInfo{Name: "anyone"},
		},
		{
			name:         "impersonating-sa-allowed",
			impersonator: &user.DefaultInfo{Name: "sa-impersonater"},
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
			impersonator: &user.DefaultInfo{Name: "sa-impersonater"},
			expectedUser: &user.DefaultInfo{Name: "sa-impersonater"},
			requests: []testRequest{
				{
					request: getPodRequest,
					expectedAttributes: []authorizer.Attributes{
						newImpersonateOnAttrs(getPodRequest, "arbitrary-node"),
						&impersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "nodes", Name: "node1"}, mode: "arbitrary-node"},
						&legacyImpersonateAttrs{AttributesRecord: authorizer.AttributesRecord{Resource: "users", Name: "system:node:node1"}},
					},
					expectCache:  &expectCache{},
					expectedCode: http.StatusForbidden,
				},
			},
			impersonationUser: &user.DefaultInfo{Name: "system:node:node1"},
		},
		{
			name:         "impersonating-node-not-allowed-action",
			impersonator: &user.DefaultInfo{Name: "node-impersonater"},
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
					expectCache:  &expectCache{},
					expectedCode: http.StatusForbidden,
				},
			},
			impersonationUser: &user.DefaultInfo{Name: "system:node:node1"},
		},
		{
			name:         "impersonating-node-allowed",
			impersonator: &user.DefaultInfo{Name: "node-impersonater"},
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
			impersonator: &user.DefaultInfo{
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
					expectCache:  &expectCache{},
					expectedCode: http.StatusForbidden,
				},
			},
		},
		{
			name: "allowed-userextras",
			impersonator: &user.DefaultInfo{
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
			impersonator: &user.DefaultInfo{
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
			impersonator: &user.DefaultInfo{
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
					expectCache:  &expectCache{},
					expectedCode: http.StatusForbidden,
				},
			},
			impersonationUser: &user.DefaultInfo{Name: "system:node:node1"},
		},
		{
			name:         "allowed-legacy-impersonator",
			impersonator: &user.DefaultInfo{Name: "legacy-impersonater"},
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
			impersonator: &user.DefaultInfo{
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
	server := httptest.NewServer(constrainedAuthorizer.authorizeHandler(t))
	defer server.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, requestInfo := range tc.requests {
				requestCtx := request.WithUser(request.NewContext(), tc.impersonator)
				requestCtx = request.WithRequestInfo(requestCtx, requestInfo.request)
				// passing request context to authorizer.
				constrainedAuthorizer.withRequestContext(requestCtx)
				req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, server.URL, nil)
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tc.name, err)
					return
				}
				if len(tc.impersonationUser.Name) > 0 {
					req.Header.Add(authenticationapi.ImpersonateUserHeader, tc.impersonationUser.Name)
				}
				for _, group := range tc.impersonationUser.Groups {
					req.Header.Add(authenticationapi.ImpersonateGroupHeader, group)
				}
				for extraKey, values := range tc.impersonationUser.Extra {
					for _, value := range values {
						req.Header.Add(authenticationapi.ImpersonateUserExtraHeaderPrefix+extraKey, value)
					}
				}
				if len(tc.impersonationUser.UID) > 0 {
					req.Header.Add(authenticationapi.ImpersonateUIDHeader, tc.impersonationUser.UID)
				}

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tc.name, err)
					return
				}
				if resp.StatusCode != requestInfo.expectedCode {
					t.Errorf("%s: expected %v, actual %v", tc.name, requestInfo.expectedCode, resp.StatusCode)
					return
				}

				// set expected users in attributes to impersonator if it is not specifically set.
				if requestInfo.expectedAttributesUser == nil {
					requestInfo.expectedAttributesUser = tc.impersonator
				}

				expectedUser := tc.expectedUser
				if requestInfo.expectedUserInfo != nil {
					expectedUser = requestInfo.expectedUserInfo
				}

				assertUserInfo(t, expectedUser, constrainedAuthorizer.actualUser)
				constrainedAuthorizer.assertAttributes(t, requestInfo)
				constrainedAuthorizer.assertCache(t, tc.impersonator, tc.impersonationUser, requestInfo.expectCache)
			}
			constrainedAuthorizer.clear()
		})
	}
}

func assertUserInfo(t *testing.T, expect, actual user.Info) {
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
