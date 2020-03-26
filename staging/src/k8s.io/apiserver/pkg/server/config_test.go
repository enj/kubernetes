/*
Copyright 2017 The Kubernetes Authors.

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

package server

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/waitgroup"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/audit/policy"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestAuthorizeClientBearerTokenNoops(t *testing.T) {
	// All of these should do nothing (not panic, no side-effects)
	cfgGens := []func() *rest.Config{
		func() *rest.Config { return nil },
		func() *rest.Config { return &rest.Config{} },
		func() *rest.Config { return &rest.Config{BearerToken: "mu"} },
	}
	authcGens := []func() *AuthenticationInfo{
		func() *AuthenticationInfo { return nil },
		func() *AuthenticationInfo { return &AuthenticationInfo{} },
	}
	authzGens := []func() *AuthorizationInfo{
		func() *AuthorizationInfo { return nil },
		func() *AuthorizationInfo { return &AuthorizationInfo{} },
	}
	for _, cfgGen := range cfgGens {
		for _, authcGen := range authcGens {
			for _, authzGen := range authzGens {
				pConfig := cfgGen()
				pAuthc := authcGen()
				pAuthz := authzGen()
				AuthorizeClientBearerToken(pConfig, pAuthc, pAuthz)
				if before, after := authcGen(), pAuthc; !reflect.DeepEqual(before, after) {
					t.Errorf("AuthorizeClientBearerToken(%v, %#+v, %v) changed %#+v", pConfig, pAuthc, pAuthz, *before)
				}
				if before, after := authzGen(), pAuthz; !reflect.DeepEqual(before, after) {
					t.Errorf("AuthorizeClientBearerToken(%v, %v, %#+v) changed %#+v", pConfig, pAuthc, pAuthz, *before)
				}
			}
		}
	}
}

func TestNewWithDelegate(t *testing.T) {
	delegateConfig := NewConfig(codecs)
	delegateConfig.ExternalAddress = "192.168.10.4:443"
	delegateConfig.PublicAddress = net.ParseIP("192.168.10.4")
	delegateConfig.LegacyAPIGroupPrefixes = sets.NewString("/api")
	delegateConfig.LoopbackClientConfig = &rest.Config{}
	clientset := fake.NewSimpleClientset()
	if clientset == nil {
		t.Fatal("unable to create fake client set")
	}

	delegateConfig.HealthzChecks = append(delegateConfig.HealthzChecks, healthz.NamedCheck("delegate-health", func(r *http.Request) error {
		return fmt.Errorf("delegate failed healthcheck")
	}))

	sharedInformers := informers.NewSharedInformerFactory(clientset, delegateConfig.LoopbackClientConfig.Timeout)
	delegateServer, err := delegateConfig.Complete(sharedInformers).New("test", NewEmptyDelegate())
	if err != nil {
		t.Fatal(err)
	}
	delegateServer.Handler.NonGoRestfulMux.HandleFunc("/foo", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	delegatePostStartHookChan := make(chan struct{})
	delegateServer.AddPostStartHookOrDie("delegate-post-start-hook", func(context PostStartHookContext) error {
		defer close(delegatePostStartHookChan)
		return nil
	})

	// this wires up swagger
	delegateServer.PrepareRun()

	wrappingConfig := NewConfig(codecs)
	wrappingConfig.ExternalAddress = "192.168.10.4:443"
	wrappingConfig.PublicAddress = net.ParseIP("192.168.10.4")
	wrappingConfig.LegacyAPIGroupPrefixes = sets.NewString("/api")
	wrappingConfig.LoopbackClientConfig = &rest.Config{}

	wrappingConfig.HealthzChecks = append(wrappingConfig.HealthzChecks, healthz.NamedCheck("wrapping-health", func(r *http.Request) error {
		return fmt.Errorf("wrapping failed healthcheck")
	}))

	sharedInformers = informers.NewSharedInformerFactory(clientset, wrappingConfig.LoopbackClientConfig.Timeout)
	wrappingServer, err := wrappingConfig.Complete(sharedInformers).New("test", delegateServer)
	if err != nil {
		t.Fatal(err)
	}
	wrappingServer.Handler.NonGoRestfulMux.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	wrappingPostStartHookChan := make(chan struct{})
	wrappingServer.AddPostStartHookOrDie("wrapping-post-start-hook", func(context PostStartHookContext) error {
		defer close(wrappingPostStartHookChan)
		return nil
	})

	stopCh := make(chan struct{})
	defer close(stopCh)
	wrappingServer.PrepareRun()
	wrappingServer.RunPostStartHooks(stopCh)

	server := httptest.NewServer(wrappingServer.Handler)
	defer server.Close()

	// Wait for the hooks to finish before checking the response
	<-delegatePostStartHookChan
	<-wrappingPostStartHookChan
	expectedPaths := []string{
		"/apis",
		"/bar",
		"/foo",
		"/healthz",
		"/healthz/delegate-health",
		"/healthz/log",
		"/healthz/ping",
		"/healthz/poststarthook/delegate-post-start-hook",
		"/healthz/poststarthook/generic-apiserver-start-informers",
		"/healthz/poststarthook/wrapping-post-start-hook",
		"/healthz/wrapping-health",
		"/livez",
		"/livez/delegate-health",
		"/livez/log",
		"/livez/ping",
		"/livez/poststarthook/delegate-post-start-hook",
		"/livez/poststarthook/generic-apiserver-start-informers",
		"/livez/poststarthook/wrapping-post-start-hook",
		"/metrics",
		"/readyz",
		"/readyz/delegate-health",
		"/readyz/log",
		"/readyz/ping",
		"/readyz/poststarthook/delegate-post-start-hook",
		"/readyz/poststarthook/generic-apiserver-start-informers",
		"/readyz/poststarthook/wrapping-post-start-hook",
		"/readyz/shutdown",
	}
	checkExpectedPathsAtRoot(server.URL, expectedPaths, t)
	checkPath(server.URL+"/healthz", http.StatusInternalServerError, `[+]ping ok
[+]log ok
[-]wrapping-health failed: reason withheld
[-]delegate-health failed: reason withheld
[+]poststarthook/generic-apiserver-start-informers ok
[+]poststarthook/delegate-post-start-hook ok
[+]poststarthook/wrapping-post-start-hook ok
healthz check failed
`, t)

	checkPath(server.URL+"/healthz/delegate-health", http.StatusInternalServerError, `internal server error: delegate failed healthcheck
`, t)
	checkPath(server.URL+"/healthz/wrapping-health", http.StatusInternalServerError, `internal server error: wrapping failed healthcheck
`, t)
	checkPath(server.URL+"/healthz/poststarthook/delegate-post-start-hook", http.StatusOK, `ok`, t)
	checkPath(server.URL+"/healthz/poststarthook/wrapping-post-start-hook", http.StatusOK, `ok`, t)
	checkPath(server.URL+"/foo", http.StatusForbidden, ``, t)
	checkPath(server.URL+"/bar", http.StatusUnauthorized, ``, t)
}

func checkPath(url string, expectedStatusCode int, expectedBody string, t *testing.T) {
	t.Run(url, func(t *testing.T) {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		dump, _ := httputil.DumpResponse(resp, true)
		t.Log(string(dump))

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if e, a := expectedBody, string(body); e != a {
			t.Errorf("%q expected %v, got %v", url, e, a)
		}
		if e, a := expectedStatusCode, resp.StatusCode; e != a {
			t.Errorf("%q expected %v, got %v", url, e, a)
		}
	})
}

func checkExpectedPathsAtRoot(url string, expectedPaths []string, t *testing.T) {
	t.Run(url, func(t *testing.T) {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		dump, _ := httputil.DumpResponse(resp, true)
		t.Log(string(dump))

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		paths, ok := result["paths"].([]interface{})
		if !ok {
			t.Errorf("paths not found")
		}
		pathset := sets.NewString()
		for _, p := range paths {
			pathset.Insert(p.(string))
		}
		expectedset := sets.NewString(expectedPaths...)
		for _, p := range pathset.Difference(expectedset) {
			t.Errorf("Got %v path, which we did not expect", p)
		}
		for _, p := range expectedset.Difference(pathset) {
			t.Errorf(" Expected %v path which we did not get", p)
		}
	})
}

func TestAuthenticationAuditAnnotationsDefaultChain(t *testing.T) {
	authn := authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		return &authenticator.Response{
			User:             &user.DefaultInfo{},
			AuditAnnotations: map[string]string{"pandas": "are awesome", "dogs": "are okay"},
		}, true, nil
	})
	backend := &testBackend{}
	c := &Config{
		Authentication:     AuthenticationInfo{Authenticator: authn},
		AuditBackend:       backend,
		AuditPolicyChecker: policy.FakeChecker(auditinternal.LevelMetadata, nil),

		// avoid nil panics
		HandlerChainWaitGroup: &waitgroup.SafeWaitGroup{},
		RequestInfoResolver:   &request.RequestInfoFactory{},
		RequestTimeout:        10 * time.Second,
		LongRunningFunc:       func(_ *http.Request, _ *request.RequestInfo) bool { return false },
	}

	h := DefaultBuildHandlerChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// confirm that handlers later in the chain cannot accidentally use these functions
		testPanicChecker(t, func() { _ = request.EarlyAuditAnnotationsFrom(r.Context()) },
			"invalid attempt to get early audit annotations from context after WithAuditEvent has been called")
		testPanicChecker(t, func() { _ = request.AddEarlyAuditAnnotation(r.Context(), "", "") },
			"invalid attempt to set early audit annotation on context after WithAuditEvent has been called")

		// confirm that we have an audit event
		ae := request.AuditEventFrom(r.Context())
		if ae == nil {
			t.Error("unexpected nil audit event")
		}

		// confirm that the correct way of setting audit annotations later in the chain works as expected
		audit.LogAnnotation(ae, "snorlax", "is cool too")

		_, _ = w.Write([]byte("done"))
	}), c)
	w := &testResponseWriter{header: http.Header{}}

	h.ServeHTTP(w, &http.Request{URL: &url.URL{}})

	if ok := w.respCode == http.StatusOK && w.writeHeaderCalled && string(w.data) == "done" && len(w.header.Get(auditinternal.HeaderAuditID)) > 0; !ok {
		t.Errorf("invalid response: %#v", w)
	}
	if len(backend.events) == 0 {
		t.Error("expected audit events, got none")
	}
	for _, event := range backend.events {
		if want := map[string]string{"pandas": "are awesome", "dogs": "are okay", "snorlax": "is cool too"}; !reflect.DeepEqual(event.Annotations, want) {
			t.Errorf("event has unexpected annotations: %#v, want annotations %#v", event, want)
		}
	}
}

func testPanicChecker(t *testing.T, f func(), message string) {
	defer func() {
		r := recover()
		switch rt := r.(type) {
		case nil:
			t.Errorf("expected panic with message %q but got none", message)
		case string:
			if rt != message {
				t.Errorf("unexpected panic message %q, want %q", rt, message)
			}
		default:
			t.Errorf("unexpected panic type %#v, want string message %q", rt, message)
		}
	}()
	f()
}

type testBackend struct {
	events []*auditinternal.Event

	audit.Backend // nil panic if anything other than ProcessEvents called
}

func (b *testBackend) ProcessEvents(events ...*auditinternal.Event) bool {
	b.events = append(b.events, events...)
	return true
}

type testResponseWriter struct {
	writeHeaderCalled bool
	header            http.Header
	respCode          int
	data              []byte
}

func (r *testResponseWriter) Header() http.Header {
	return r.header
}

func (r *testResponseWriter) WriteHeader(code int) {
	r.writeHeaderCalled = true
	r.respCode = code
}

func (r *testResponseWriter) Write(in []byte) (int, error) {
	if !r.writeHeaderCalled {
		r.WriteHeader(http.StatusOK)
	}
	r.data = append(r.data, in...)
	return len(in), nil
}
