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
	transports       map[tlsCacheKey]tlsCacheEntry
	strongTransports map[tlsCacheKey]*atomicTransportHolder
}

// tlsCacheEntry pairs a weak pointer with eviction tracking state.
type tlsCacheEntry struct {
	wp         weak.Pointer[atomicTransportHolder]
	generation uint64

	// holderDead is set to true when the holder is GC'd.  It is reset to
	// false when a new caller retrieves the holder from the cache (reviving it).
	holderDead *atomic.Bool

	// liveTransports tracks the number of *http.Transport instances that are
	// still alive.  Incremented when a transport is created, decremented when
	// a transport is GC'd.
	liveTransports *atomic.Int64

	// evict deletes this cache entry and cancels the cert rotation goroutine,
	// but only when both holderDead is true and liveTransports is 0.
	evict func()
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
		return nil, true // key exists but holder was GC'd
	}

	// Revive: a new caller is holding the holder, so mark it alive again
	// and register a new cleanup for this caller's reference.
	e.holderDead.Store(false)
	runtime.AddCleanup(t, func(_ struct{}) {
		e.holderDead.Store(true)
		e.evict()
	}, struct{}{})

	return t, true
}

func (c *tlsTransportCache) setLocked(key tlsCacheKey, transport *atomicTransportHolder, holderDead *atomic.Bool, liveTransports *atomic.Int64, evict func()) uint64 {
	if !clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC) {
		c.strongTransports[key] = transport
		return 0
	}

	var gen uint64
	if e, ok := c.transports[key]; ok {
		gen = e.generation + 1
	}
	c.transports[key] = tlsCacheEntry{
		wp:             weak.Make(transport),
		generation:     gen,
		holderDead:     holderDead,
		liveTransports: liveTransports,
		evict:          evict,
	}
	return gen
}

func (c *tlsTransportCache) lenLocked() int {
	if !clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC) {
		return len(c.strongTransports)
	}

	return len(c.transports)
}

const idleConnsPerHost = 25

var tlsCache = &tlsTransportCache{
	transports:       make(map[tlsCacheKey]tlsCacheEntry),
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

	// cacheEviction tracks the liveness of both the atomicTransportHolder and
	// its *http.Transport(s). The cache entry should only be evicted (and
	// the cert rotation goroutine cancelled) when both the holder and all
	// of its transports have been garbage collected.
	//
	// holderDead is set to true by runtime.AddCleanup on the holder.
	// liveTransports is incremented for each *http.Transport created and
	// decremented by runtime.AddCleanup when each transport is GC'd.
	// tryEvict only proceeds when holderDead is true AND liveTransports is 0.
	var holderDead atomic.Bool
	var liveTransports atomic.Int64

	// evict is set after setLocked to capture the generation. Callbacks
	// call through this pointer so they always use the final version.
	var evict func()

	// transportCleanup is called by registerTransportCleanup when any
	// *http.Transport created by this holder is garbage collected.
	transportCleanup := func() {
		liveTransports.Add(-1)
		if evict != nil {
			evict()
		}
	}

	// transportCreated is called by the holder whenever a new *http.Transport
	// is created (initial creation and after CA rotation).
	transportCreated := func() {
		liveTransports.Add(1)
	}

	var transport *atomicTransportHolder
	if config.TLS.ReloadCAFiles && tlsConfig != nil && tlsConfig.RootCAs != nil && len(config.TLS.CAFile) > 0 {
		transport = newAtomicTransportHolder(config.TLS.CAFile, config.TLS.CAData, httpTransport, transportCleanup, transportCreated)
	} else {
		transport = newAtomicTransportHolderWithoutReload(httpTransport, transportCleanup, transportCreated)
	}

	if canCache {
		// evict only deletes this entry (checked via generation), and only
		// when both the holder and all transports are dead.
		// It is set as a closure after setLocked to capture the generation.
		// Callbacks (transportCleanup, holder AddCleanup, and getLocked revive)
		// all call through the entry's evict pointer.
		var evictOnce sync.Once
		evictFn := func(gen uint64) {
			if !holderDead.Load() {
				return
			}
			if liveTransports.Load() > 0 {
				return
			}

			evictOnce.Do(func() {
				if cancel != nil {
					cancel()
				}

				c.mu.Lock()
				defer c.mu.Unlock()

				if e, ok := c.transports[key]; ok && e.generation == gen {
					delete(c.transports, key)
				}
			})
		}

		gen := c.setLocked(key, transport, &holderDead, &liveTransports, nil)
		evictWithGen := func() { evictFn(gen) }

		// Update the cache entry's evict pointer now that we have the generation.
		e := c.transports[key]
		e.evict = evictWithGen
		c.transports[key] = e

		// Also wire up the transportCleanup → evict path.
		evict = evictWithGen

		// When the holder is GC'd (caller dropped it), mark it dead and try
		// to evict. If any transport is still alive (someone unwrapped
		// it), eviction will be deferred until all transports are also GC'd.
		runtime.AddCleanup(transport, func(_ struct{}) {
			holderDead.Store(true)
			evictWithGen()
		}, struct{}{})
	}

	return transport, nil
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
