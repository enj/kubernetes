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
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	clientgofeaturegate "k8s.io/client-go/features"
	"k8s.io/client-go/tools/metrics"
	"k8s.io/klog/v2"
)

// TlsTransportCache caches TLS http.RoundTrippers different configurations. The
// same RoundTripper will be returned for configs with identical TLS options If
// the config has no custom TLS options, http.DefaultTransport is returned.
type tlsTransportCache struct {
	mu               sync.Mutex
	transports       map[tlsCacheKey]*tlsCacheEntry           // GC-enabled: weak refs
	strongTransports map[tlsCacheKey]*atomicTransportHolder   // GC-disabled: strong refs
}

const idleConnsPerHost = 25

var tlsCache = &tlsTransportCache{
	transports:       make(map[tlsCacheKey]*tlsCacheEntry),
	strongTransports: make(map[tlsCacheKey]*atomicTransportHolder),
}

type tlsCacheKey struct {
	insecure           bool
	caData             string
	caFile             string
	certData           string
	keyData            string `datapolicy:"security-key"`
	certFile           string
	keyFile            string
	serverName         string
	nextProtos         string
	disableCompression bool
	// these functions are wrapped to allow them to be used as map keys
	getCert *GetCertHolder
	dial    *DialHolder
}

func (t tlsCacheKey) String() string {
	keyText := "<none>"
	if len(t.keyData) > 0 {
		keyText = "<redacted>"
	}
	return fmt.Sprintf("insecure:%v, caData:%#v, caFile:%s, certData:%#v, keyData:%s, serverName:%s, disableCompression:%t, getCert:%p, dial:%p",
		t.insecure, t.caData, t.caFile, t.certData, keyText, t.serverName, t.disableCompression, t.getCert, t.dial)
}

func (c *tlsTransportCache) get(config *Config) (http.RoundTripper, error) {
	key, canCache, err := tlsConfigKey(config)
	if err != nil {
		return nil, err
	}

	if canCache {
		// Ensure we only create a single transport for the given TLS options
		c.mu.Lock()
		defer c.mu.Unlock()
		defer metrics.TransportCacheEntries.Observe(c.lenLocked())

		// See if we already have a custom transport for this config
		if t, ok := c.getLocked(key); ok {
			if t != nil {
				metrics.TransportCreateCalls.Increment("hit")
				return t, nil
			}
			metrics.TransportCreateCalls.Increment("miss-gc")
		} else {
			metrics.TransportCreateCalls.Increment("miss")
		}
	} else {
		metrics.TransportCreateCalls.Increment("uncacheable")
	}

	// Get the TLS options for this client config
	tlsConfig, err := TLSConfigFor(config)
	if err != nil {
		return nil, err
	}
	// The options didn't require a custom TLS config
	if tlsConfig == nil && config.DialHolder == nil && config.Proxy == nil {
		return http.DefaultTransport, nil
	}

	var dial func(ctx context.Context, network, address string) (net.Conn, error)
	if config.DialHolder != nil {
		dial = config.DialHolder.Dial
	} else {
		dial = (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}

	// If we use are reloading files, we need to handle certificate rotation properly
	// TODO(jackkleeman): We can also add rotation here when config.HasCertCallback() is true
	var cancel context.CancelFunc
	if config.TLS.ReloadTLSFiles && tlsConfig != nil && tlsConfig.GetClientCertificate != nil {
		// The TLS cache is a singleton, so sharing the same name for all of its
		// background activity seems okay.
		logger := klog.Background().WithName("tls-transport-cache")
		dynamicCertDialer := certRotatingDialer(logger, tlsConfig.GetClientCertificate, dial)
		tlsConfig.GetClientCertificate = dynamicCertDialer.GetClientCertificate
		dial = dynamicCertDialer.connDialer.DialContext
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		go dynamicCertDialer.run(ctx.Done())
	}

	proxy := http.ProxyFromEnvironment
	if config.Proxy != nil {
		proxy = config.Proxy
	}

	httpTransport := utilnet.SetTransportDefaults(&http.Transport{
		Proxy:               proxy,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		MaxIdleConnsPerHost: idleConnsPerHost,
		DialContext:         dial,
		DisableCompression:  config.DisableCompression,
	})

	entry := &tlsCacheEntry{}
	var holder *atomicTransportHolder
	if config.TLS.ReloadCAFiles && tlsConfig != nil && tlsConfig.RootCAs != nil && len(config.TLS.CAFile) > 0 {
		holder = newAtomicTransportHolder(config.TLS.CAFile, config.TLS.CAData, httpTransport, entry.onTransportCreated, entry.onTransportCleanup)
	} else {
		holder = newAtomicTransportHolderWithoutReload(httpTransport, entry.onTransportCreated, entry.onTransportCleanup)
	}

	if canCache {
		c.setLocked(key, holder, entry)
		entry.evict = func() { c.evictEntryIfUnused(key, entry, cancel) }
	} else if cancel != nil {
		// Uncacheable transports still need cert rotation goroutine cleanup.
		// Same lifecycle tracking as cached entries, but evict just calls cancel.
		entry.markAliveWithCleanup(holder)
		entry.evict = cancel
	}

	// Preserves pre-GC behavior: cached entries live forever, cert rotation
	// goroutines run indefinitely.
	if !clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC) {
		entry.evict = nil
	}

	return holder, nil
}

func (c *tlsTransportCache) getLocked(key tlsCacheKey) (*atomicTransportHolder, bool) {
	if !clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC) {
		v, ok := c.strongTransports[key]
		return v, ok
	}

	e, ok := c.transports[key]
	if !ok {
		return nil, false
	}
	t := e.wp.Value()
	if t == nil {
		return nil, true
	}

	// A new caller obtained the holder — reset holderDead so eviction is
	// blocked until this caller also drops it.
	e.markAliveWithCleanup(t)

	return t, true
}

func (c *tlsTransportCache) setLocked(key tlsCacheKey, holder *atomicTransportHolder, entry *tlsCacheEntry) {
	if !clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC) {
		c.strongTransports[key] = holder
		return
	}

	entry.wp = weak.Make(holder)
	c.transports[key] = entry
	entry.markAliveWithCleanup(holder)
}

// evictEntryIfUnused re-checks eviction conditions under c.mu.
//
// This re-check is necessary because markAliveWithCleanup (called from
// getLocked under c.mu) may have reset holderDead between tryEvict's
// lock-free atomic checks and this call.
func (c *tlsTransportCache) evictEntryIfUnused(key tlsCacheKey, entry *tlsCacheEntry, cancel context.CancelFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !entry.holderDead.Load() {
		return
	}
	if entry.liveTransports.Load() > 0 {
		return
	}
	if c.transports[key] != entry {
		return
	}

	delete(c.transports, key)

	if cancel != nil {
		cancel()
	}
}

func (c *tlsTransportCache) lenLocked() int {
	if !clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC) {
		return len(c.strongTransports)
	}

	return len(c.transports)
}

// tlsConfigKey returns a unique key for tls.Config objects returned from TLSConfigFor
func tlsConfigKey(c *Config) (tlsCacheKey, bool, error) {
	// Make sure ca/key/cert content is loaded
	if err := loadTLSFiles(c); err != nil {
		return tlsCacheKey{}, false, err
	}

	if c.Proxy != nil {
		// cannot determine equality for functions
		return tlsCacheKey{}, false, nil
	}

	k := tlsCacheKey{
		insecure:           c.TLS.Insecure,
		serverName:         c.TLS.ServerName,
		nextProtos:         strings.Join(c.TLS.NextProtos, ","),
		disableCompression: c.DisableCompression,
		getCert:            c.TLS.GetCertHolder,
		dial:               c.DialHolder,
	}

	if c.TLS.ReloadTLSFiles {
		k.certFile = c.TLS.CertFile
		k.keyFile = c.TLS.KeyFile
	} else {
		k.certData = string(c.TLS.CertData)
		k.keyData = string(c.TLS.KeyData)
	}

	if c.TLS.ReloadCAFiles {
		// When reloading CA files, include CA file path in cache key instead of CA data
		// This allows the CA to be reloaded from disk on each transport creation
		k.caFile = c.TLS.CAFile
	} else {
		// When not reloading, cache the CA data directly
		k.caData = string(c.TLS.CAData)
	}

	return k, true, nil
}

// tlsCacheEntry manages the GC-based lifecycle of a cached transport.
//
// Invariants:
//   - evict is only called when holderDead is true AND liveTransports is 0.
//   - holderDead is false while any caller holds the *atomicTransportHolder.
//     It is set to true by a runtime.AddCleanup callback when the holder
//     becomes unreachable, and reset to false by markAliveWithCleanup when
//     a new caller obtains the holder from the cache.
//   - liveTransports is incremented for each *http.Transport created
//     (initial + CA rotations) and decremented when each is GC'd.
//     Because the holder stores its transport strongly, liveTransports > 0
//     whenever the holder is alive.
//   - For cached entries, evict acquires c.mu and re-checks holderDead and
//     liveTransports to prevent races with concurrent markAliveWithCleanup
//     calls (which also run under c.mu via getLocked).
//   - For uncacheable entries, evict is a simple cancel call. No lock is
//     needed because there is no cache map to protect and no revive path.
type tlsCacheEntry struct {
	wp             weak.Pointer[atomicTransportHolder]
	holderDead     atomic.Bool
	liveTransports atomic.Int64
	evict          func()
}

// tryEvict is the lock-free fast-path for eviction. The atomic checks avoid
// calling evict (which may acquire c.mu) when eviction is clearly not needed.
func (e *tlsCacheEntry) tryEvict() {
	if !e.holderDead.Load() {
		return
	}
	if e.liveTransports.Load() > 0 {
		return
	}
	if e.evict != nil {
		e.evict()
	}
}

func (e *tlsCacheEntry) onTransportCreated() {
	e.liveTransports.Add(1)
}

func (e *tlsCacheEntry) onTransportCleanup() {
	e.liveTransports.Add(-1)
	e.tryEvict()
}

// markAliveWithCleanup resets holderDead and registers a cleanup that will
// set it back to true when this caller drops the holder. Must be called
// under c.mu for cached entries to prevent races with evictEntryIfUnused.
func (e *tlsCacheEntry) markAliveWithCleanup(holder *atomicTransportHolder) {
	e.holderDead.Store(false)
	addCleanup(holder, func() {
		e.holderDead.Store(true)
		e.tryEvict()
	})
}

func addCleanup[T any](ptr *T, cleanup func()) {
	runtime.AddCleanup(ptr, func(_ struct{}) { cleanup() }, struct{}{})
}
