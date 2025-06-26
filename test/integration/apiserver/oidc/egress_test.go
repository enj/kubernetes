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

package oidc

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func runEgressProxy(t testing.TB, udsName string) {
	t.Helper()

	l, err := net.Listen("unix", udsName)
	if err != nil {
		t.Fatal(err)
	}

	var called atomic.Bool
	httpConnectProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)

		if r.Method != http.MethodConnect {
			http.Error(w, "this proxy only supports CONNECT passthrough", http.StatusMethodNotAllowed)
			return
		}

		backendConn, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = backendConn.Close() }()

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}

		requestHijackedConn, _, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = requestHijackedConn.Close() }()

		// use t.Errorf for all errors after this Write since the client may think the connection is good
		_, err = requestHijackedConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			t.Errorf("unexpected established error: %v", err)
			return
		}

		writerComplete := make(chan struct{})
		readerComplete := make(chan struct{})

		go func() {
			_, err := io.Copy(backendConn, requestHijackedConn)
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("unexpected writer error: %v", err)
			}
			close(writerComplete)
		}()

		go func() {
			_, err := io.Copy(requestHijackedConn, backendConn)
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("unexpected reader error: %v", err)
			}
			close(readerComplete)
		}()

		// Wait for one half the connection to exit. Once it does,
		// the defer will clean up the other half of the connection.
		select {
		case <-writerComplete:
		case <-readerComplete:
		}
	})

	server := http.Server{Handler: httpConnectProxy}

	t.Cleanup(func() {
		if !called.Load() {
			t.Errorf("egress proxy was not called")
		}

		err := server.Shutdown(context.Background())
		t.Logf("shutdown exit error: %v", err)
	})

	err = server.Serve(l)
	t.Logf("egress exit error: %v", err)
}
