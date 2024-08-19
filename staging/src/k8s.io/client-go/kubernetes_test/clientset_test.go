/*
Copyright 2022 The Kubernetes Authors.

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

package kubernetes_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	crv1 "k8s.io/apiextensions-apiserver/examples/client-go/pkg/apis/cr/v1"
	crv1client "k8s.io/apiextensions-apiserver/examples/client-go/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

func TestClientUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expect    string
	}{
		{
			name:   "empty",
			expect: rest.DefaultKubernetesUserAgent(),
		},
		{
			name:      "custom",
			userAgent: "test-agent",
			expect:    "test-agent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				userAgent := r.Header.Get("User-Agent")
				if userAgent != tc.expect {
					t.Errorf("User Agent expected: %s got: %s", tc.expect, userAgent)
					http.Error(w, "Unexpected user agent", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte("{}"))
			}))
			ts.Start()
			defer ts.Close()

			gv := corev1.SchemeGroupVersion
			config := &rest.Config{
				Host: ts.URL,
			}
			config.GroupVersion = &gv
			config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
			config.UserAgent = tc.userAgent
			config.ContentType = "application/json"

			client, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatalf("failed to create REST client: %v", err)
			}
			_, err = client.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				t.Error(err)
			}
			_, err = client.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				t.Error(err)
			}
		})
	}

}

func TestClientContentType(t *testing.T) {
	createPodFunc := func(t *testing.T, config *rest.Config) {
		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			t.Fatalf("failed to create REST client: %v", err)
		}

		_, err = client.CoreV1().Pods("panda").
			Create(context.TODO(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "snorlax"}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}

	createExampleViaRESTClientFunc := func(t *testing.T, config *rest.Config) {
		kubeClient, err := kubernetes.NewForConfig(config)
		if err != nil {
			t.Fatalf("failed to create REST client: %v", err)
		}

		client := crv1client.New(kubeClient.CoreV1().RESTClient())

		_, err = client.CrV1().Examples("panda").
			Create(context.TODO(), &crv1.Example{ObjectMeta: metav1.ObjectMeta{Name: "snorlax"}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name              string
		createFunc        func(*testing.T, *rest.Config)
		contentType       string
		expectedPath      string
		expectContentType string
		expectBody        string
	}{
		{
			name:              "default",
			createFunc:        createPodFunc,
			contentType:       "",
			expectedPath:      "/api/v1/namespaces/panda/pods",
			expectContentType: "application/vnd.kubernetes.protobuf",
			expectBody:        "k8s\x00\n\t\n\x02v1\x12\x03Pod\x12I\n\x17\n\asnorlax\x12\x00\x1a\x00\"\x00*\x002\x008\x00B\x00\x12\x1c\x1a\x002\x00B\x00J\x00R\x00X\x00`\x00h\x00\x82\x01\x00\x8a\x01\x00\x9a\x01\x00\xc2\x01\x00\x1a\x10\n\x00\x1a\x00\"\x00*\x002\x00J\x00Z\x00r\x00\x1a\x00\"\x00",
		},
		{
			name:              "json",
			createFunc:        createPodFunc,
			contentType:       "application/json",
			expectedPath:      "/api/v1/namespaces/panda/pods",
			expectContentType: "application/json",
			expectBody: `{"kind":"Pod","apiVersion":"v1","metadata":{"name":"snorlax","creationTimestamp":null},"spec":{"containers":null},"status":{}}
`,
		},
		{
			name:              "default via RESTClient",
			createFunc:        createExampleViaRESTClientFunc,
			contentType:       "",
			expectedPath:      "/api/v1/namespaces/panda/examples",
			expectContentType: "application/json",
			expectBody: `{"metadata":{"name":"snorlax","creationTimestamp":null},"spec":{"foo":"","bar":false},"status":{}}
`,
		},
		{
			name:              "json via RESTClient",
			createFunc:        createExampleViaRESTClientFunc,
			contentType:       "application/json",
			expectedPath:      "/api/v1/namespaces/panda/examples",
			expectContentType: "application/json",
			expectBody: `{"metadata":{"name":"snorlax","creationTimestamp":null},"spec":{"foo":"","bar":false},"status":{}}
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Uint64
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)

				if got, want := r.URL.Path, tc.expectedPath; got != want {
					t.Errorf("unexpected path, got=%q, want=%q", got, want)
				}

				if got, want := r.Header.Get("content-type"), tc.expectContentType; got != want {
					t.Errorf("unexpected content-type, got=%q, want=%q", got, want)
				}

				if r.Body == nil {
					t.Fatal("request body is nil")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				_ = r.Body.Close()
				if diff := cmp.Diff(tc.expectBody, string(body)); len(diff) > 0 {
					t.Errorf("body diff (-want, +got):\n%s", diff)
				}

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("{}"))
			}))
			ts.Start()
			defer ts.Close()

			config := &rest.Config{
				Host:          ts.URL,
				ContentConfig: rest.ContentConfig{ContentType: tc.contentType},
			}

			tc.createFunc(t, config)

			if calls.Load() != 1 {
				t.Errorf("unexpected handler call count: %d", calls.Load())
			}
		})
	}
}
