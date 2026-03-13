/*
Copyright 2015 The Kubernetes Authors.

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

package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"k8s.io/apimachinery/pkg/util/wait"
	clientgofeaturegate "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	"k8s.io/client-go/tools/metrics"
)

// --- metric recording helpers ---

type recordingCreateCalls struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingCreateCalls) Increment(result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, result)
}

func (r *recordingCreateCalls) reset() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.calls
	r.calls = nil
	return c
}

type recordingCacheGCCalls struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingCacheGCCalls) Increment(result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, result)
}

func (r *recordingCacheGCCalls) reset() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.calls
	r.calls = nil
	return c
}

type recordingCertRotationGCCalls struct {
	count atomic.Int64
}

func (r *recordingCertRotationGCCalls) Increment() {
	r.count.Add(1)
}

func installFakeMetrics(t *testing.T) (*recordingCreateCalls, *recordingCacheGCCalls, *recordingCertRotationGCCalls) {
	createCalls := &recordingCreateCalls{}
	gcCalls := &recordingCacheGCCalls{}
	rotationGCCalls := &recordingCertRotationGCCalls{}

	origCreate := metrics.TransportCreateCalls
	origGC := metrics.TransportCacheGCCalls
	origRotationGC := metrics.TransportCertRotationGCCalls
	metrics.TransportCreateCalls = createCalls
	metrics.TransportCacheGCCalls = gcCalls
	metrics.TransportCertRotationGCCalls = rotationGCCalls
	t.Cleanup(func() {
		metrics.TransportCreateCalls = origCreate
		metrics.TransportCacheGCCalls = origGC
		metrics.TransportCertRotationGCCalls = origRotationGC
	})
	return createCalls, gcCalls, rotationGCCalls
}

// --- tests ---

func TestTLSConfigKey(t *testing.T) {

	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, true)
	// Make sure config fields that don't affect the tls config don't affect the cache key
	identicalConfigurations := map[string]*Config{
		"empty":          {},
		"basic":          {Username: "bob", Password: "password"},
		"bearer":         {BearerToken: "token"},
		"user agent":     {UserAgent: "useragent"},
		"transport":      {Transport: http.DefaultTransport},
		"wrap transport": {WrapTransport: func(http.RoundTripper) http.RoundTripper { return nil }},
	}
	for nameA, valueA := range identicalConfigurations {
		for nameB, valueB := range identicalConfigurations {
			keyA, canCache, err := tlsConfigKey(valueA)
			if err != nil {
				t.Errorf("Unexpected error for %q: %v", nameA, err)
				continue
			}
			if !canCache {
				t.Errorf("Unexpected canCache=false")
				continue
			}
			keyB, canCache, err := tlsConfigKey(valueB)
			if err != nil {
				t.Errorf("Unexpected error for %q: %v", nameB, err)
				continue
			}
			if !canCache {
				t.Errorf("Unexpected canCache=false")
				continue
			}
			if keyA != keyB {
				t.Errorf("Expected identical cache keys for %q and %q, got:\n\t%s\n\t%s", nameA, nameB, keyA, keyB)
				continue
			}
			if keyA != (tlsCacheKey{}) {
				t.Errorf("Expected empty cache keys for %q and %q, got:\n\t%s\n\t%s", nameA, nameB, keyA, keyB)
				continue
			}
		}
	}

	// Make sure config fields that affect the tls config affect the cache key
	dialer := net.Dialer{}
	getCert := &GetCertHolder{GetCert: func() (*tls.Certificate, error) { return nil, nil }}
	caFile := writeCAFile(t, []byte(testCACert1))
	uniqueConfigurations := map[string]*Config{
		"proxy":                         {Proxy: func(request *http.Request) (*url.URL, error) { return nil, nil }},
		"no tls":                        {},
		"dialer":                        {DialHolder: &DialHolder{Dial: dialer.DialContext}},
		"dialer2":                       {DialHolder: &DialHolder{Dial: func(ctx context.Context, network, address string) (net.Conn, error) { return nil, nil }}},
		"insecure":                      {TLS: TLSConfig{Insecure: true}},
		"cadata 1":                      {TLS: TLSConfig{CAData: []byte{1}}},
		"cadata 2":                      {TLS: TLSConfig{CAData: []byte{2}}},
		"with only ca file":             {TLS: TLSConfig{CAFile: caFile}},
		"with both ca file and ca data": {TLS: TLSConfig{CAFile: caFile, CAData: []byte(testCACert1)}},
		"cert 1, key 1": {
			TLS: TLSConfig{
				CertData: []byte{1},
				KeyData:  []byte{1},
			},
		},
		"cert 1, key 1, servername 1": {
			TLS: TLSConfig{
				CertData:   []byte{1},
				KeyData:    []byte{1},
				ServerName: "1",
			},
		},
		"cert 1, key 1, servername 2": {
			TLS: TLSConfig{
				CertData:   []byte{1},
				KeyData:    []byte{1},
				ServerName: "2",
			},
		},
		"cert 1, key 2": {
			TLS: TLSConfig{
				CertData: []byte{1},
				KeyData:  []byte{2},
			},
		},
		"cert 2, key 1": {
			TLS: TLSConfig{
				CertData: []byte{2},
				KeyData:  []byte{1},
			},
		},
		"cert 2, key 2": {
			TLS: TLSConfig{
				CertData: []byte{2},
				KeyData:  []byte{2},
			},
		},
		"cadata 1, cert 1, key 1": {
			TLS: TLSConfig{
				CAData:   []byte{1},
				CertData: []byte{1},
				KeyData:  []byte{1},
			},
		},
		"getCert1": {
			TLS: TLSConfig{
				KeyData:       []byte{1},
				GetCertHolder: getCert,
			},
		},
		"getCert2": {
			TLS: TLSConfig{
				KeyData:       []byte{1},
				GetCertHolder: &GetCertHolder{GetCert: func() (*tls.Certificate, error) { return nil, nil }},
			},
		},
		"getCert1, key 2": {
			TLS: TLSConfig{
				KeyData:       []byte{2},
				GetCertHolder: getCert,
			},
		},
		"http2, http1.1": {TLS: TLSConfig{NextProtos: []string{"h2", "http/1.1"}}},
		"http1.1-only":   {TLS: TLSConfig{NextProtos: []string{"http/1.1"}}},
	}
	for nameA, valueA := range uniqueConfigurations {
		for nameB, valueB := range uniqueConfigurations {
			keyA, canCacheA, err := tlsConfigKey(valueA)
			if err != nil {
				t.Errorf("Unexpected error for %q: %v", nameA, err)
				continue
			}
			keyB, canCacheB, err := tlsConfigKey(valueB)
			if err != nil {
				t.Errorf("Unexpected error for %q: %v", nameB, err)
				continue
			}

			shouldCacheA := valueA.Proxy == nil
			if shouldCacheA != canCacheA {
				t.Error("Unexpected canCache=false for " + nameA)
			}

			configIsNotEmpty := !reflect.DeepEqual(*valueA, Config{})
			if keyA == (tlsCacheKey{}) && shouldCacheA && configIsNotEmpty {
				t.Errorf("Expected non-empty cache keys for %q and %q, got:\n\t%s\n\t%s", nameA, nameB, keyA, keyB)
				continue
			}

			// Make sure we get the same key on the same config
			if nameA == nameB {
				if keyA != keyB {
					t.Errorf("Expected identical cache keys for %q and %q, got:\n\t%s\n\t%s", nameA, nameB, keyA, keyB)
				}
				if canCacheA != canCacheB {
					t.Errorf("Expected identical canCache %q and %q, got:\n\t%v\n\t%v", nameA, nameB, canCacheA, canCacheB)
				}
				continue
			}

			if canCacheA && canCacheB {
				if keyA == keyB {
					t.Errorf("Expected unique cache keys for %q and %q, got:\n\t%s\n\t%s", nameA, nameB, keyA, keyB)
					continue
				}
			}
		}
	}
}

func TestTLSConfigKeyCARotationDisabled(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, false)

	caFile := writeCAFile(t, []byte(testCACert1))

	// When feature is disabled, CAFile-only config resolves CAData via
	// loadTLSFiles, so two configs with the same file content get the same key.
	config1 := &Config{TLS: TLSConfig{CAFile: caFile}}
	config2 := &Config{TLS: TLSConfig{CAData: []byte(testCACert1)}}

	if err := loadTLSFiles(config1); err != nil {
		t.Fatal(err)
	}
	if err := loadTLSFiles(config2); err != nil {
		t.Fatal(err)
	}

	key1, canCache1, err := tlsConfigKey(config1)
	if err != nil || !canCache1 {
		t.Fatalf("unexpected: err=%v, canCache=%v", err, canCache1)
	}

	key2, canCache2, err := tlsConfigKey(config2)
	if err != nil || !canCache2 {
		t.Fatalf("unexpected: err=%v, canCache=%v", err, canCache2)
	}

	if key1 != key2 {
		t.Error("Expected same cache key when feature is disabled (CAFile resolved to CAData)")
	}
	if config1.TLS.ReloadCAFiles {
		t.Error("Expected ReloadCAFiles=false when feature gate is disabled")
	}
}

func newTestTLSTransportCache() *tlsTransportCache {
	return &tlsTransportCache{
		transports:       make(map[tlsCacheKey]weak.Pointer[trackedTransport]),
		strongTransports: make(map[tlsCacheKey]http.RoundTripper),
	}
}

// TestTLSTransportCacheCARotation tests transport cache behavior with CA rotation
func TestTLSTransportCacheCARotation(t *testing.T) {

	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, true)
	caFile := writeCAFile(t, []byte(testCACert1))
	testCases := []struct {
		name            string
		config          *Config
		expectCAReload  bool
		expectCacheable bool
	}{
		{
			name: "CA rotation should be enabled when only the CAFile is set",
			config: &Config{
				TLS: TLSConfig{
					CAFile: caFile,
				},
			},
			expectCAReload:  true,
			expectCacheable: true,
		},
		{
			name: "CA rotation should be disabled when both CAFile and CAData are set",
			config: &Config{
				TLS: TLSConfig{
					CAFile: caFile,
					CAData: []byte(testCACert1),
				},
			},
			expectCAReload:  false,
			expectCacheable: true,
		},
		{
			name: "CA rotation should be disabled when only the CAData is set",
			config: &Config{
				TLS: TLSConfig{
					CAData: []byte(testCACert1),
				},
			},
			expectCAReload:  false,
			expectCacheable: true,
		},
		{
			name: "no TLS config",
			config: &Config{
				TLS: TLSConfig{},
			},
			expectCAReload:  false,
			expectCacheable: false, // No TLS config means default transport
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			createCalls, _, _ := installFakeMetrics(t)
			tlsCaches := newTestTLSTransportCache()

			rt, err := tlsCaches.get(tc.config)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if !tc.expectCacheable {
				if rt != http.DefaultTransport {
					t.Errorf("Expected default transport, got %T", rt)
				}
				// Empty config is still cacheable (canCache=true) but returns
				// DefaultTransport before reaching the cache store. The miss
				// metric fires because there's no existing entry for this key.
				if calls := createCalls.reset(); len(calls) != 1 || calls[0] != "miss" {
					t.Errorf("expected [miss], got %v", calls)
				}
				return
			}

			if calls := createCalls.reset(); len(calls) != 1 || calls[0] != "miss" {
				t.Errorf("expected [miss] on first get, got %v", calls)
			}

			// Unwrap trackedTransport if present (GC-enabled path wraps the transport).
			inner := rt
			if ct, ok := rt.(*trackedTransport); ok {
				inner = ct.rt
			}
			if tc.expectCAReload {
				if _, ok := inner.(*atomicTransportHolder); !ok {
					t.Errorf("Expected atomicTransportHolder for CA rotation, got %T", inner)
				}
				if !tc.config.TLS.ReloadCAFiles {
					t.Errorf("Expected ReloadCAFiles to be true, got %v", tc.config.TLS.ReloadCAFiles)
				}
			} else {
				if _, ok := inner.(*http.Transport); !ok {
					t.Errorf("Expected *http.Transport without CA rotation, got %T", inner)
				}
			}

			// Second call should be a cache hit.
			rt2, err := tlsCaches.get(tc.config)
			if err != nil {
				t.Fatalf("Unexpected error on second call: %v", err)
			}
			if rt != rt2 {
				t.Error("Expected same transport instance from cache")
			}
			if calls := createCalls.reset(); len(calls) != 1 || calls[0] != "hit" {
				t.Errorf("expected [hit] on second get, got %v", calls)
			}

			requireCacheLen(t, tlsCaches, 1)
		})
	}
}

func TestTLSTransportCacheCARotationDisabled(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, false)
	createCalls, _, _ := installFakeMetrics(t)

	caFile := writeCAFile(t, []byte(testCACert1))
	cache := newTestTLSTransportCache()

	rt, err := cache.get(&Config{TLS: TLSConfig{CAFile: caFile}})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if calls := createCalls.reset(); len(calls) != 1 || calls[0] != "miss" {
		t.Errorf("expected [miss], got %v", calls)
	}

	inner := rt
	if ct, ok := rt.(*trackedTransport); ok {
		inner = ct.rt
	}
	if _, ok := inner.(*atomicTransportHolder); ok {
		t.Error("Expected plain *http.Transport when CA rotation feature gate is disabled, got atomicTransportHolder")
	}

	// Second call should hit.
	rt2, err := cache.get(&Config{TLS: TLSConfig{CAFile: caFile}})
	if err != nil {
		t.Fatal(err)
	}
	if rt != rt2 {
		t.Error("expected cache hit to return same transport")
	}
	if calls := createCalls.reset(); len(calls) != 1 || calls[0] != "hit" {
		t.Errorf("expected [hit], got %v", calls)
	}
}

func TestEmptyCAFileRotationLifecycle(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, true)

	emptyFile := writeCAFile(t, []byte{})

	config := &Config{
		TLS: TLSConfig{
			CAFile: emptyFile,
		},
	}

	tlsCaches := newTestTLSTransportCache()

	rt, err := tlsCaches.get(config)
	if err != nil {
		t.Fatalf("Unexpected error getting transport: %v", err)
	}

	inner := rt
	if ct, ok := rt.(*trackedTransport); ok {
		inner = ct.rt
	}

	holder, ok := inner.(*atomicTransportHolder)
	if !ok {
		t.Fatalf("Expected atomicTransportHolder, got %T", inner)
	}

	initialTransport := holder.getTransport(context.Background())

	if initialTransport.TLSClientConfig == nil || initialTransport.TLSClientConfig.RootCAs == nil {
		t.Fatal("Expected RootCAs to be non-nil for an empty CA file (should be an empty CertPool)")
	}
	emptyPool := x509.NewCertPool()
	if !initialTransport.TLSClientConfig.RootCAs.Equal(emptyPool) {
		t.Fatal("Expected initially empty RootCAs")
	}

	if err := os.WriteFile(emptyFile, []byte(testCACert1), 0644); err != nil {
		t.Fatalf("Failed to write to CA file: %v", err)
	}

	holder.mu.Lock()
	holder.transportLastChecked = time.Now().Add(-time.Hour)
	holder.mu.Unlock()

	refreshedTransport := holder.getTransport(context.Background())

	if refreshedTransport.TLSClientConfig.RootCAs.Equal(emptyPool) {
		t.Fatal("Expected RootCAs to be populated after writing valid cert data and refreshing")
	}
}

// TestCacheHoldAfterCARotation verifies that holding the *atomicTransportHolder
// keeps the cache entry alive even after CA rotation swaps the inner transport.
func TestCacheHoldAfterCARotation(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, true)
	_, gcCalls, _ := installFakeMetrics(t)

	caFile := writeCAFile(t, []byte(testCACert1))

	pollCacheSizeWithGC(t, tlsCache, 0) // clean start

	rt, err := New(&Config{TLS: TLSConfig{ServerName: "reload-test", CAFile: caFile}})
	if err != nil {
		t.Fatal(err)
	}

	requireCacheLen(t, tlsCache, 1)

	holder := rt.(*trackedTransport).rt.(*atomicTransportHolder)

	originalInner := holder.getTransport(context.Background())
	if originalInner == nil {
		t.Fatal("expected non-nil transport")
	}

	// Simulate CA rotation.
	if err := os.WriteFile(caFile, []byte(testCACert2), 0644); err != nil {
		t.Fatal(err)
	}
	holder.mu.Lock()
	holder.transportLastChecked = time.Now().Add(-time.Hour)
	holder.mu.Unlock()

	newInner := holder.getTransport(context.Background())
	if newInner == nil {
		t.Fatal("expected non-nil transport after rotation")
	}
	if newInner == originalInner {
		t.Fatal("expected transport to change after CA rotation")
	}

	originalInner = nil //nolint:ineffassign

	// Cache entry must survive because the holder is alive.
	for range 5 {
		runtime.GC()
	}
	requireCacheLen(t, tlsCache, 1)

	runtime.KeepAlive(rt)

	gcCalls.reset() // clear any calls from earlier GC activity
	pollCacheSizeWithGC(t, tlsCache, 0)

	if calls := gcCalls.reset(); len(calls) != 1 || calls[0] != "deleted" {
		t.Errorf("expected [deleted] after eviction, got %v", calls)
	}
}

// TestCacheGCDisabledNoEviction verifies that with the GC feature gate disabled,
// cache entries are stored in strongTransports and never evicted.
func TestCacheGCDisabledNoEviction(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, false)
	createCalls, gcCalls, _ := installFakeMetrics(t)

	cache := newTestTLSTransportCache()

	rt, err := cache.get(&Config{TLS: TLSConfig{ServerName: "gc-disabled-test"}})
	if err != nil {
		t.Fatal(err)
	}

	if calls := createCalls.reset(); len(calls) != 1 || calls[0] != "miss" {
		t.Errorf("expected [miss], got %v", calls)
	}

	// No trackedTransport wrapper when GC is disabled.
	if _, ok := rt.(*trackedTransport); ok {
		t.Error("expected plain transport, not *trackedTransport, when GC is disabled")
	}

	// Second call should hit.
	rt2, err := cache.get(&Config{TLS: TLSConfig{ServerName: "gc-disabled-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if rt != rt2 {
		t.Error("expected cache hit to return same transport")
	}
	if calls := createCalls.reset(); len(calls) != 1 || calls[0] != "hit" {
		t.Errorf("expected [hit], got %v", calls)
	}

	requireCacheLen(t, cache, 1)

	// GC should not evict strong entries.
	runtime.KeepAlive(rt)
	for range 10 {
		runtime.GC()
	}
	requireCacheLen(t, cache, 1)

	if calls := gcCalls.reset(); len(calls) != 0 {
		t.Errorf("expected no GC cache calls when GC is disabled, got %v", calls)
	}
}

// TestCacheReviveAfterDrop verifies that when rt1 is still alive (via KeepAlive),
// a second get() for the same key is a deterministic cache hit.
func TestCacheReviveAfterDrop(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	createCalls, _, _ := installFakeMetrics(t)

	pollCacheSizeWithGC(t, tlsCache, 0)

	config := &Config{TLS: TLSConfig{ServerName: "revive-test"}}

	rt1, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	requireCacheLen(t, tlsCache, 1)
	createCalls.reset()

	// rt1 is alive here, so the weak pointer must still resolve.
	rt2, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if rt1 != rt2 {
		t.Error("expected same transport (cache hit) since rt1 is still alive")
	}
	if calls := createCalls.reset(); len(calls) != 1 || calls[0] != "hit" {
		t.Errorf("expected [hit], got %v", calls)
	}
	requireCacheLen(t, tlsCache, 1)

	runtime.KeepAlive(rt1)
	runtime.KeepAlive(rt2)
	pollCacheSizeWithGC(t, tlsCache, 0)
}

// TestUncacheableCertRotationLeak verifies that the cert rotation goroutine
// is stopped when an uncacheable transport is garbage collected.
func TestUncacheableCertRotationLeak(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	_, _, rotationGCCalls := installFakeMetrics(t)

	certFile := writeCAFile(t, []byte(certData))
	keyFile := writeCAFile(t, []byte(keyData))

	baseline := runtime.NumGoroutine()

	rt, err := tlsCache.get(&Config{
		TLS: TLSConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		},
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	afterCreate := runtime.NumGoroutine()
	if afterCreate <= baseline {
		t.Fatalf("expected goroutine count to increase after creating transport with cert rotation, got baseline=%d after=%d", baseline, afterCreate)
	}

	runtime.KeepAlive(rt)

	err = wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 10*time.Second, true, func(_ context.Context) (bool, error) {
		runtime.GC()
		return runtime.NumGoroutine() <= baseline, nil
	})
	if err != nil {
		t.Errorf("goroutine leak: cert rotation goroutine was not stopped for uncacheable transport (baseline=%d current=%d)", baseline, runtime.NumGoroutine())
	}

	if n := rotationGCCalls.count.Load(); n != 1 {
		t.Errorf("expected TransportCertRotationGCCalls=1, got %d", n)
	}
}

// TestCacheableCertRotationLeak verifies that the cert rotation goroutine
// is stopped when a cacheable transport with cert rotation is garbage collected.
// This exercises the canCache=true && cancel != nil path through setLocked.
func TestCacheableCertRotationLeak(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	_, gcCalls, rotationGCCalls := installFakeMetrics(t)

	certFile := writeCAFile(t, []byte(certData))
	keyFile := writeCAFile(t, []byte(keyData))

	pollCacheSizeWithGC(t, tlsCache, 0) // clean start

	baseline := runtime.NumGoroutine()

	// CertFile+KeyFile triggers ReloadTLSFiles and the cert rotation goroutine.
	// No Proxy means canCache=true.
	rt, err := New(&Config{
		TLS: TLSConfig{
			CertFile:   certFile,
			KeyFile:    keyFile,
			ServerName: "cacheable-cert-rotation-test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	requireCacheLen(t, tlsCache, 1)

	afterCreate := runtime.NumGoroutine()
	if afterCreate <= baseline {
		t.Fatalf("expected goroutine count to increase after creating transport with cert rotation, got baseline=%d after=%d", baseline, afterCreate)
	}

	runtime.KeepAlive(rt)

	pollCacheSizeWithGC(t, tlsCache, 0)

	err = wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 10*time.Second, true, func(_ context.Context) (bool, error) {
		runtime.GC()
		return runtime.NumGoroutine() <= baseline, nil
	})
	if err != nil {
		t.Errorf("goroutine leak: cert rotation goroutine was not stopped for cacheable transport (baseline=%d current=%d)", baseline, runtime.NumGoroutine())
	}

	if n := rotationGCCalls.count.Load(); n != 1 {
		t.Errorf("expected TransportCertRotationGCCalls=1, got %d", n)
	}
	if calls := gcCalls.reset(); len(calls) != 1 || calls[0] != "deleted" {
		t.Errorf("expected [deleted], got %v", calls)
	}
}

// TestCacheGCDisabledCertRotationNoCancel verifies that with the GC feature gate
// disabled, the cert rotation goroutine is NOT stopped (pre-GC behavior).
func TestCacheGCDisabledCertRotationNoCancel(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, false)
	_, _, rotationGCCalls := installFakeMetrics(t)

	certFile := writeCAFile(t, []byte(certData))
	keyFile := writeCAFile(t, []byte(keyData))

	cache := newTestTLSTransportCache()

	rt, err := cache.get(&Config{
		TLS: TLSConfig{
			CertFile:   certFile,
			KeyFile:    keyFile,
			ServerName: "gc-disabled-cert-rotation",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	runtime.KeepAlive(rt)
	for range 10 {
		runtime.GC()
	}

	// Cancel should never fire when GC is disabled.
	if n := rotationGCCalls.count.Load(); n != 0 {
		t.Errorf("expected TransportCertRotationGCCalls=0 when GC disabled, got %d", n)
	}
}

// TestCacheStaleEvictionSkipped verifies that when a GC cleanup fires for an
// old entry after a new get() has replaced it, the deletion is skipped.
func TestCacheStaleEvictionSkipped(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	_, gcCalls, _ := installFakeMetrics(t)

	pollCacheSizeWithGC(t, tlsCache, 0) // clean start

	serverName := "stale-eviction-test"

	// Create first entry.
	rt1, err := New(&Config{TLS: TLSConfig{ServerName: serverName}})
	if err != nil {
		t.Fatal(err)
	}
	requireCacheLen(t, tlsCache, 1)

	// Drop rt1 and wait for it to be GC'd + entry deleted.
	runtime.KeepAlive(rt1)
	pollCacheSizeWithGC(t, tlsCache, 0)
	gcCalls.reset() // clear the "deleted" from this eviction

	// Create second entry for the same key.
	rt2, err := New(&Config{TLS: TLSConfig{ServerName: serverName}})
	if err != nil {
		t.Fatal(err)
	}
	requireCacheLen(t, tlsCache, 1)

	// Force more GC passes — if any stale cleanup from rt1 fires now, it
	// should see c.transports[key] != wp and skip the deletion.
	for range 10 {
		runtime.GC()
	}
	requireCacheLen(t, tlsCache, 1) // must not have been deleted

	// Any "skipped" calls would indicate a stale cleanup attempted and was blocked.
	// It's not deterministic whether the stale cleanup fires at all (it may have
	// already fired during pollCacheSizeWithGC above), but if it does, it must be "skipped".
	for _, call := range gcCalls.reset() {
		if call == "deleted" {
			t.Error("stale cleanup wrongly deleted the replacement entry")
		}
	}

	runtime.KeepAlive(rt2)
	pollCacheSizeWithGC(t, tlsCache, 0)
}

func TestCacheLeak(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	_, gcCalls, _ := installFakeMetrics(t)

	pollCacheSizeWithGC(t, tlsCache, 0) // clean start

	rt1, err := New(&Config{TLS: TLSConfig{ServerName: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	rt2, err := New(&Config{TLS: TLSConfig{ServerName: "2"}})
	if err != nil {
		t.Fatal(err)
	}
	rt3, err := New(&Config{TLS: TLSConfig{ServerName: "1"}})
	if err != nil {
		t.Fatal(err)
	}

	requireCacheLen(t, tlsCache, 2) // rt1 and rt2 (rt3 is the same as rt1)

	var wg wait.Group
	var d net.Dialer
	var rts []http.RoundTripper
	var rtsLock sync.Mutex
	for i := range 1_000 { // outer loop forces cache miss via dialer
		dh := &DialHolder{Dial: d.DialContext}
		for range i%7 + 1 { // inner loop exercises each cache value having 1 to N references
			wg.Start(func() {
				rt, err := New(&Config{DialHolder: dh})
				if err != nil {
					panic(err)
				}
				rtsLock.Lock()
				rts = append(rts, rt) // keep a live reference to the round tripper
				rtsLock.Unlock()
			})
		}
	}
	wg.Wait()

	requireCacheLen(t, tlsCache, 1_000+2) // rts and rt1 and rt2 (rt3 is the same as rt1)

	gcCalls.reset() // clear any calls from setup
	runtime.KeepAlive(rts) // prevent round trippers from being GC'd too early

	pollCacheSizeWithGC(t, tlsCache, 2) // rt1 and rt2 (rt3 is the same as rt1)

	calls := gcCalls.reset()
	deletedCount := 0
	for _, c := range calls {
		if c == "deleted" {
			deletedCount++
		}
	}
	if deletedCount != 1_000 {
		t.Errorf("expected 1000 deleted calls, got %d (total calls: %d)", deletedCount, len(calls))
	}

	runtime.KeepAlive(rt1)
	runtime.KeepAlive(rt2)
	runtime.KeepAlive(rt3)

	pollCacheSizeWithGC(t, tlsCache, 0)

	calls = gcCalls.reset()
	deletedCount = 0
	for _, c := range calls {
		if c == "deleted" {
			deletedCount++
		}
	}
	if deletedCount != 2 {
		t.Errorf("expected 2 deleted calls for rt1/rt2, got %d", deletedCount)
	}
}

func requireCacheLen(t *testing.T, c *tlsTransportCache, want int) {
	t.Helper()

	if cacheLen(c) != want {
		t.Fatalf("cache len %d, want %d", cacheLen(c), want)
	}
}

func cacheLen(c *tlsTransportCache) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.lenLocked()
}

func pollCacheSizeWithGC(t *testing.T, c *tlsTransportCache, want int) {
	t.Helper()

	if err := wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 10*time.Second, true, func(_ context.Context) (done bool, _ error) {
		runtime.GC() // run the garbage collector so the cleanups run
		return cacheLen(c) == want, nil
	}); err != nil {
		t.Fatalf("cache len %d, want %d: %v", cacheLen(c), want, err)
	}

	// make sure the cache size is stable even when more GC's happen
	// three times should be enough to make the test flake if the implementation is buggy
	for range 3 {
		runtime.GC()
	}
	requireCacheLen(t, c, want)
}
