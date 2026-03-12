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
	transports       map[tlsCacheKey]*tlsCacheEntry
	strongTransports map[tlsCacheKey]*atomicTransportHolder
}

// tlsCacheEntry tracks a cached atomicTransportHolder via a weak pointer and
// manages eviction. The entry is only evicted when both the holder and all of
// its *http.Transport instances have been garbage collected.
type tlsCacheEntry struct {
	wp             weak.Pointer[atomicTransportHolder]
	holderDead     atomic.Bool
	liveTransports atomic.Int64
	evictOnce      sync.Once
	evict          func()
}

// tryEvict runs the eviction function if both the holder is dead and all
// transports have been garbage collected.
func (e *tlsCacheEntry) tryEvict() {
	if !e.holderDead.Load() {
		return
	}
	if e.liveTransports.Load() > 0 {
		return
	}
	e.evictOnce.Do(func() {
		if e.evict != nil {
			e.evict()
		}
	})
}

// onTransportCreated is called when a new *http.Transport is created (initial
// creation and after CA rotation).
func (e *tlsCacheEntry) onTransportCreated() {
	e.liveTransports.Add(1)
}

// revive marks the holder as alive again and registers a new cleanup so that
// when this caller drops the holder, the eviction check runs again.
func (e *tlsCacheEntry) revive(holder *atomicTransportHolder) {
	e.holderDead.Store(false)
	addCleanup(holder, func() {
		e.holderDead.Store(true)
		e.tryEvict()
	})
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
	e.revive(t)

	return t, true
}

func (c *tlsTransportCache) setLocked(key tlsCacheKey, transport *atomicTransportHolder, entry *tlsCacheEntry) {
	if !clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC) {
		c.strongTransports[key] = transport
		return
	}

	entry.wp = weak.Make(transport)
	c.transports[key] = entry
}

func (c *tlsTransportCache) lenLocked() int {
	if !clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC) {
		return len(c.strongTransports)
	}

	return len(c.transports)
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

	// onTransportCleanup decrements the live transport count and tries to evict.
	onTransportCleanup := func() {
		entry.liveTransports.Add(-1)
		entry.tryEvict()
	}

	var transport *atomicTransportHolder
	if config.TLS.ReloadCAFiles && tlsConfig != nil && tlsConfig.RootCAs != nil && len(config.TLS.CAFile) > 0 {
		transport = newAtomicTransportHolder(config.TLS.CAFile, config.TLS.CAData, httpTransport, onTransportCleanup, entry.onTransportCreated)
	} else {
		transport = newAtomicTransportHolderWithoutReload(httpTransport, onTransportCleanup, entry.onTransportCreated)
	}

	if canCache {
		c.setLocked(key, transport, entry)

		entry.evict = func() {
			if cancel != nil {
				cancel()
			}

			c.mu.Lock()
			defer c.mu.Unlock()
			if c.transports[key] == entry {
				delete(c.transports, key)
			}
		}

		entry.revive(transport)
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

func addCleanup[T any](ptr *T, cleanup func()) {
	runtime.AddCleanup(ptr, func(_ struct{}) { cleanup() }, struct{}{})
}
