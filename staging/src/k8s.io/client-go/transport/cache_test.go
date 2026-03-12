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
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	clientgofeaturegate "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
)

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

// newTestTLSTransportCache creates a new tlsTransportCache for testing.
func newTestTLSTransportCache() *tlsTransportCache {
	return &tlsTransportCache{
		transports:       make(map[tlsCacheKey]*tlsCacheEntry),
		strongTransports: make(map[tlsCacheKey]*atomicTransportHolder),
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
			tlsCaches := newTestTLSTransportCache()

			rt, err := tlsCaches.get(tc.config)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if !tc.expectCacheable {
				if rt != http.DefaultTransport {
					t.Errorf("Expected default transport, got %T", rt)
				}
				return
			}

			holder, ok := rt.(*atomicTransportHolder)
			if !ok {
				t.Fatalf("Expected *atomicTransportHolder, got %T", rt)
			}
			if tc.expectCAReload {
				if holder.skipReload {
					t.Error("Expected skipReload=false for CA rotation")
				}
				if !tc.config.TLS.ReloadCAFiles {
					t.Errorf("Expected ReloadCAFiles to be true, got %v", tc.config.TLS.ReloadCAFiles)
				}
			} else {
				if !holder.skipReload {
					t.Error("Expected skipReload=true without CA rotation")
				}
			}

			// Test caching: second call should return the same instance
			rt2, err := tlsCaches.get(tc.config)
			if err != nil {
				t.Fatalf("Unexpected error on second call: %v", err)
			}

			if rt != rt2 {
				t.Error("Expected same transport instance from cache")
			}

			// Verify cache size
			tlsCaches.mu.Lock()
			cacheSize := tlsCaches.lenLocked()
			tlsCaches.mu.Unlock()

			expectedCacheSize := 1
			if !tc.expectCacheable {
				expectedCacheSize = 0
			}

			if cacheSize != expectedCacheSize {
				t.Errorf("Expected %d transports in cache, got %d", expectedCacheSize, cacheSize)
			}
		})
	}
}

func TestTLSTransportCacheCARotationDisabled(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, false)

	caFile := writeCAFile(t, []byte(testCACert1))
	cache := newTestTLSTransportCache()

	rt, err := cache.get(&Config{TLS: TLSConfig{CAFile: caFile}})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	holder, ok := rt.(*atomicTransportHolder)
	if !ok {
		t.Fatalf("Expected *atomicTransportHolder, got %T", rt)
	}
	if !holder.skipReload {
		t.Error("Expected skipReload=true when CA rotation feature gate is disabled")
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

	holder, ok := rt.(*atomicTransportHolder)
	if !ok {
		t.Fatalf("Expected *atomicTransportHolder, got %T", rt)
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

// TestCacheUnwrapHoldInner verifies that unwrapping the atomicTransportHolder
// via WrappedRoundTripper and holding only the inner *http.Transport keeps the
// cache entry alive. The transport being alive in any way must prevent the
// cache entry from being evicted.
func TestCacheUnwrapHoldInner(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, true)

	tests := []struct {
		name   string
		config *Config
	}{
		{
			name:   "without CA rotation",
			config: &Config{TLS: TLSConfig{ServerName: "unwrap-test-plain"}},
		},
		{
			name:   "with CA rotation",
			config: &Config{TLS: TLSConfig{ServerName: "unwrap-test-ca", CAFile: writeCAFile(t, []byte(testCACert1))}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pollCacheSizeWithGC(t, tlsCache, 0) // clean start

			rt, err := New(tt.config)
			if err != nil {
				t.Fatal(err)
			}

			requireCacheLen(t, tlsCache, 1)

			// Unwrap to get the inner *http.Transport.
			holder := rt.(*atomicTransportHolder)
			inner := holder.WrappedRoundTripper()
			if _, ok := inner.(*http.Transport); !ok {
				t.Fatalf("expected *http.Transport, got %T", inner)
			}

			// Drop the holder. The caller still holds the inner *http.Transport.
			rt = nil     //nolint:ineffassign
			holder = nil //nolint:ineffassign

			// The cache entry must survive because the inner *http.Transport
			// is still alive — the transport being held must prevent eviction.
			for range 5 {
				runtime.GC()
			}
			requireCacheLen(t, tlsCache, 1) // must still be 1

			runtime.KeepAlive(inner)

			pollCacheSizeWithGC(t, tlsCache, 0) // now inner is unreachable
		})
	}
}

// TestCacheHoldAfterCARotation verifies that holding the *atomicTransportHolder
// keeps the cache entry alive even after CA rotation swaps the inner transport.
// After rotation, the old transport is no longer referenced by the holder, so
// dropping references to the old transport should not evict the cache entry.
func TestCacheHoldAfterCARotation(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, true)

	caFile := writeCAFile(t, []byte(testCACert1))

	pollCacheSizeWithGC(t, tlsCache, 0) // clean start

	rt, err := New(&Config{TLS: TLSConfig{ServerName: "reload-test", CAFile: caFile}})
	if err != nil {
		t.Fatal(err)
	}

	requireCacheLen(t, tlsCache, 1)

	holder := rt.(*atomicTransportHolder)

	// Grab the original inner transport.
	originalInner := holder.getTransport(context.Background())
	if originalInner == nil {
		t.Fatal("expected non-nil transport")
	}

	// Simulate CA rotation: write new CA data and force a refresh.
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

	// Drop reference to the old inner transport.
	originalInner = nil //nolint:ineffassign

	// The holder still holds the new transport strongly. The cache entry
	// must survive because the holder is alive (caller holds rt) and
	// the new transport is alive (holder holds it strongly).
	for range 5 {
		runtime.GC()
	}
	requireCacheLen(t, tlsCache, 1) // holder is alive, cache entry must survive

	runtime.KeepAlive(rt)

	pollCacheSizeWithGC(t, tlsCache, 0) // now rt is unreachable
}

// TestCacheUnwrapAfterCARotation verifies the interaction of CA rotation with
// unwrapping. After CA rotation, if the caller drops the holder but holds the
// new inner transport, the cache entry must survive. Only when the final
// rotated transport is also dropped should the entry be evicted.
func TestCacheUnwrapAfterCARotation(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, true)

	caFile := writeCAFile(t, []byte(testCACert1))

	pollCacheSizeWithGC(t, tlsCache, 0) // clean start

	rt, err := New(&Config{TLS: TLSConfig{ServerName: "unwrap-rotate-test", CAFile: caFile}})
	if err != nil {
		t.Fatal(err)
	}

	requireCacheLen(t, tlsCache, 1)

	holder := rt.(*atomicTransportHolder)

	// Simulate CA rotation.
	if err := os.WriteFile(caFile, []byte(testCACert2), 0644); err != nil {
		t.Fatal(err)
	}
	holder.mu.Lock()
	holder.transportLastChecked = time.Now().Add(-time.Hour)
	holder.mu.Unlock()

	// Unwrap to get the new (rotated) inner transport.
	newInner := holder.getTransport(context.Background())
	if newInner == nil {
		t.Fatal("expected non-nil transport after rotation")
	}

	// Drop the holder. Caller only holds the rotated *http.Transport.
	rt = nil     //nolint:ineffassign
	holder = nil //nolint:ineffassign

	// The cache entry must survive because the rotated transport is alive.
	for range 5 {
		runtime.GC()
	}
	requireCacheLen(t, tlsCache, 1) // rotated transport is alive, cache must survive

	runtime.KeepAlive(newInner)

	pollCacheSizeWithGC(t, tlsCache, 0) // now newInner is unreachable
}

// TestCacheEvictReviveRace verifies that the eviction logic correctly handles
// the case where revive runs between tryEvict's atomic checks and the actual
// eviction. This simulates the race by directly calling the entry's evict
// function after revive has reset holderDead.
//
// The race scenario (without the lock re-check fix):
//  1. holderDead=true, liveTransports=0 — tryEvict passes both atomic checks
//  2. revive sets holderDead=false (a new caller got the holder from cache)
//  3. evict runs anyway and deletes the cache entry
//
// With the fix, evict re-checks holderDead under c.mu and sees false, so it
// does not delete.
func TestCacheEvictReviveRace(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)

	pollCacheSizeWithGC(t, tlsCache, 0) // clean start

	serverName := "race-test"

	// Create entry in the cache.
	rt, err := New(&Config{TLS: TLSConfig{ServerName: serverName}})
	if err != nil {
		t.Fatal(err)
	}
	requireCacheLen(t, tlsCache, 1)

	// Grab the entry and its evict function.
	cfg := &Config{TLS: TLSConfig{ServerName: serverName}}
	key, _, _ := tlsConfigKey(cfg)
	tlsCache.mu.Lock()
	entry := tlsCache.transports[key]
	evictFn := entry.evict
	tlsCache.mu.Unlock()

	// Simulate the exact race sequence:
	// 1. tryEvict passes the atomic checks (holderDead=true, liveTransports=0)
	//    We simulate this by setting holderDead=true and decrementing liveTransports.
	entry.holderDead.Store(true)
	entry.liveTransports.Add(-1) // was 1, now 0

	// 2. Before evict runs, a new caller does get() → getLocked → revive,
	//    which sets holderDead=false and increments liveTransports.
	rt2, err := New(&Config{TLS: TLSConfig{ServerName: serverName}})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Now evict runs (simulating what tryEvict would do after passing
	//    the atomic checks but before the actual eviction).
	evictFn()

	// The entry should NOT have been evicted because revive ran in step 2.
	tlsCache.mu.Lock()
	currentEntry := tlsCache.transports[key]
	tlsCache.mu.Unlock()

	if currentEntry != entry {
		t.Error("entry was replaced — evict raced with revive and wrongly evicted the entry")
	}
	requireCacheLen(t, tlsCache, 1)

	runtime.KeepAlive(rt)
	runtime.KeepAlive(rt2)
	pollCacheSizeWithGC(t, tlsCache, 0)
}

// TestCacheReviveAfterDrop verifies that after all callers drop a holder,
// a new get() for the same key revives the cache entry. The new caller
// should get the same transport back (cache hit), and dropping it should
// eventually evict the entry.
func TestCacheReviveAfterDrop(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)

	pollCacheSizeWithGC(t, tlsCache, 0)

	config := &Config{TLS: TLSConfig{ServerName: "revive-test"}}

	rt1, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	requireCacheLen(t, tlsCache, 1)

	// Drop rt1. The holder becomes unreachable but the cache entry may
	// still exist (weak pointer not guaranteed to go nil).
	runtime.KeepAlive(rt1)

	// A new caller requests the same config. If the weak pointer still
	// resolves, it should get a cache hit with the holder revived.
	// If the weak pointer went nil, it gets a new holder (miss-gc).
	// Either way the cache should have exactly 1 entry.
	rt2, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	requireCacheLen(t, tlsCache, 1)

	// Now drop rt2. Everything should be evicted.
	runtime.KeepAlive(rt2)
	pollCacheSizeWithGC(t, tlsCache, 0)
}

// TestUncacheableCertRotationLeak verifies that the cert rotation goroutine
// is stopped when an uncacheable transport is garbage collected.
//
// BUG: When canCache=false (e.g. Proxy is set), entry.evict is never set,
// so cancel is never called and the dynamicCertDialer goroutine runs forever.
func TestUncacheableCertRotationLeak(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)

	// Write cert and key files so ReloadTLSFiles is triggered.
	certFile := writeCAFile(t, []byte(certData))
	keyFile := writeCAFile(t, []byte(keyData))

	baseline := runtime.NumGoroutine()

	// Create an uncacheable config: Proxy makes it uncacheable,
	// CertFile+KeyFile triggers ReloadTLSFiles and the cert rotation goroutine.
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

	// The cert rotation goroutine should have started.
	afterCreate := runtime.NumGoroutine()
	if afterCreate <= baseline {
		t.Fatalf("expected goroutine count to increase after creating transport with cert rotation, got baseline=%d after=%d", baseline, afterCreate)
	}

	// Drop all references to the transport.
	runtime.KeepAlive(rt)

	// The cert rotation goroutine should be stopped after GC.
	// Poll because cleanup callbacks and goroutine shutdown are async.
	err = wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 10*time.Second, true, func(_ context.Context) (bool, error) {
		runtime.GC()
		return runtime.NumGoroutine() <= baseline, nil
	})
	if err != nil {
		t.Errorf("goroutine leak: cert rotation goroutine was not stopped for uncacheable transport (baseline=%d current=%d)", baseline, runtime.NumGoroutine())
	}
}

func TestCacheLeak(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowTLSCacheGC, true)

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

	runtime.KeepAlive(rts) // prevent round trippers from being GC'd too early

	pollCacheSizeWithGC(t, tlsCache, 2) // rt1 and rt2 (rt3 is the same as rt1)

	runtime.KeepAlive(rt1)
	runtime.KeepAlive(rt2)
	runtime.KeepAlive(rt3)

	pollCacheSizeWithGC(t, tlsCache, 0)
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

	for range 3 { // make sure the cache size is stable even when more GC's happen
		runtime.GC()
	}
	requireCacheLen(t, c, want)
}
