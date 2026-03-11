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
	"time"
	"weak"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	clientgofeaturegate "k8s.io/client-go/features"
	"k8s.io/client-go/tools/metrics"
	"k8s.io/klog/v2"
)

// cachedTransport is a concrete wrapper around http.RoundTripper that serves as the
// target for weak.Pointer in the TLS transport cache. This is needed because
// weak.Pointer requires a concrete pointer type, and the cache may hold either
// *http.Transport or *atomicTransportHolder (when CA rotation is enabled).
type cachedTransport struct {
	http.RoundTripper
}

// WrappedRoundTripper implements the utilnet.RoundTripperWrapper interface,
// allowing callers to unwrap the inner transport.
func (t *cachedTransport) WrappedRoundTripper() http.RoundTripper {
	return t.RoundTripper
}

// cacheEntry holds either a strong or weak reference to a cachedTransport,
// depending on whether the ClientsAllowTLSCacheGC feature gate is enabled.
type cacheEntry struct {
	// strong holds a strong reference, preventing GC. Used when the feature gate
	// is disabled. Mutually exclusive with weak.
	strong *cachedTransport
	// weak holds a weak reference, allowing GC. Used when the feature gate
	// is enabled. Mutually exclusive with strong.
	weak weak.Pointer[cachedTransport]
}

// value returns the cached transport, or nil if it has been garbage collected.
func (e cacheEntry) value() *cachedTransport {
	if e.strong != nil {
		return e.strong
	}
	return e.weak.Value()
}

// TlsTransportCache caches TLS http.RoundTrippers different configurations. The
// same RoundTripper will be returned for configs with identical TLS options If
// the config has no custom TLS options, http.DefaultTransport is returned.
type tlsTransportCache struct {
	mu         sync.Mutex
	transports map[tlsCacheKey]cacheEntry
}

const idleConnsPerHost = 25

var tlsCache = &tlsTransportCache{transports: make(map[tlsCacheKey]cacheEntry)}

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

	gcEnabled := clientgofeaturegate.FeatureGates().Enabled(clientgofeaturegate.ClientsAllowTLSCacheGC)

	if canCache {
		// Ensure we only create a single transport for the given TLS options
		c.mu.Lock()
		defer c.mu.Unlock()
		defer metrics.TransportCacheEntries.Observe(len(c.transports))

		// See if we already have a custom transport for this config
		if v, ok := c.transports[key]; ok {
			if t := v.value(); t != nil {
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
	var cancel context.CancelCauseFunc
	if config.TLS.ReloadTLSFiles && tlsConfig != nil && tlsConfig.GetClientCertificate != nil {
		// The TLS cache is a singleton, so sharing the same name for all of its
		// background activity seems okay.
		logger := klog.Background().WithName("tls-transport-cache")
		dynamicCertDialer := certRotatingDialer(logger, tlsConfig.GetClientCertificate, dial)
		tlsConfig.GetClientCertificate = dynamicCertDialer.GetClientCertificate
		dial = dynamicCertDialer.connDialer.DialContext
		var ctx context.Context
		ctx, cancel = context.WithCancelCause(context.Background())
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
	var rt http.RoundTripper = httpTransport

	if config.TLS.ReloadCAFiles && tlsConfig != nil && tlsConfig.RootCAs != nil && len(config.TLS.CAFile) > 0 {
		rt = newAtomicTransportHolder(config.TLS.CAFile, config.TLS.CAData, httpTransport)
	}

	transport := &cachedTransport{RoundTripper: rt}

	if canCache {
		if gcEnabled {
			// Cache a weak reference to allow garbage collection of unused transports
			c.transports[key] = cacheEntry{weak: weak.Make(transport)}
			runtime.AddCleanup(transport, func(key tlsCacheKey) {
				c.mu.Lock()
				defer c.mu.Unlock()
				delete(c.transports, key)
			}, key)
		} else {
			// Cache a strong reference (old behavior, no GC)
			c.transports[key] = cacheEntry{strong: transport}
		}
	}

	if cancel != nil {
		if gcEnabled {
			runtime.AddCleanup(transport, cancel, fmt.Errorf("transport garbage collected"))
		}
		// When GC is disabled, the cert rotation goroutine runs indefinitely
		// (matching the pre-GC behavior).
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
