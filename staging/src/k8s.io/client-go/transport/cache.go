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
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/metrics"
	"k8s.io/klog/v2"
)

// TlsTransportCache caches TLS http.RoundTrippers different configurations. The
// same RoundTripper will be returned for configs with identical TLS options If
// the config has no custom TLS options, http.DefaultTransport is returned.
type tlsTransportCache struct {
	mu         sync.Mutex
	transports map[tlsCacheKey]*tlsCacheValue
}

type tlsCacheValue struct {
	refs      uint64
	unwrapped bool
	rt        *http.Transport
}

// DialerStopCh is stop channel that is passed down to dynamic cert dialer.
// It's exposed as variable for testing purposes to avoid testing for goroutine
// leakages.
var DialerStopCh = wait.NeverStop

const idleConnsPerHost = 25

var tlsCache = &tlsTransportCache{transports: make(map[tlsCacheKey]*tlsCacheValue)}

type tlsCacheKey struct {
	insecure           bool
	caData             string
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
	return fmt.Sprintf("insecure:%v, caData:%#v, certData:%#v, keyData:%s, serverName:%s, disableCompression:%t, getCert:%p, dial:%p",
		t.insecure, t.caData, t.certData, keyText, t.serverName, t.disableCompression, t.getCert, t.dial)
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
		defer metrics.TransportCacheEntries.Observe(len(c.transports))

		// See if we already have a custom transport for this config
		if t, ok := c.transports[key]; ok {
			metrics.TransportCreateCalls.Increment("hit")
			return c.incrementRefLocked(key, t), nil
		}
		metrics.TransportCreateCalls.Increment("miss")
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
	if config.TLS.ReloadTLSFiles && tlsConfig != nil && tlsConfig.GetClientCertificate != nil {
		// The TLS cache is a singleton, so sharing the same name for all of its
		// background activity seems okay.
		logger := klog.Background().WithName("tls-transport-cache")
		dynamicCertDialer := certRotatingDialer(logger, tlsConfig.GetClientCertificate, dial)
		tlsConfig.GetClientCertificate = dynamicCertDialer.GetClientCertificate
		dial = dynamicCertDialer.connDialer.DialContext
		go dynamicCertDialer.run(DialerStopCh)
	}

	proxy := http.ProxyFromEnvironment
	if config.Proxy != nil {
		proxy = config.Proxy
	}

	transport := utilnet.SetTransportDefaults(&http.Transport{
		Proxy:               proxy,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		MaxIdleConnsPerHost: idleConnsPerHost,
		DialContext:         dial,
		DisableCompression:  config.DisableCompression,
	})

	if canCache {
		// Cache a single transport for these options
		val := &tlsCacheValue{rt: transport}
		c.transports[key] = val
		return c.incrementRefLocked(key, val), nil
	}

	return transport, nil
}

func (c *tlsTransportCache) incrementRefLocked(key tlsCacheKey, val *tlsCacheValue) *activeTransport {
	val.refs++
	a := &activeTransport{mu: &c.mu, val: val}
	arg := tlsCacheCleanupArg{key: key, val: val}
	runtime.AddCleanup(a, c.decrementRef, arg)
	return a
}

func (c *tlsTransportCache) decrementRef(arg tlsCacheCleanupArg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	arg.val.refs--
	if arg.val.refs == 0 && !arg.val.unwrapped {
		// TODO add feature gate and metrics
		delete(c.transports, arg.key)
	}
}

type tlsCacheCleanupArg struct {
	key tlsCacheKey
	val *tlsCacheValue
}

// implement all known interfaces to limit unwrapped transports
var _ interface {
	utilnet.Canceler
	utilnet.CloseIdler
	utilnet.DialGetter
	utilnet.RoundTripperWrapper
	utilnet.TLSClientConfigHolder
} = &activeTransport{}

type activeTransport struct {
	mu  *sync.Mutex
	val *tlsCacheValue
}

func (a *activeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return a.val.rt.RoundTrip(r)
}

func (a *activeTransport) WrappedRoundTripper() http.RoundTripper {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.val.unwrapped = true
	return a.val.rt
}

func (a *activeTransport) CancelRequest(r *http.Request) {
	a.val.rt.CancelRequest(r)
}

func (a *activeTransport) CloseIdleConnections() {
	a.val.rt.CloseIdleConnections()
}

func (a *activeTransport) GetDial() utilnet.DialFunc {
	if a.val.rt.DialContext == nil && a.val.rt.Dial == nil {
		return nil
	}
	return a.dial
}

func (a *activeTransport) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer, err := utilnet.DialerFor(a.val.rt)
	if err != nil {
		return nil, err // should be impossible
	}
	if dialer == nil { // should be impossible
		return nil, fmt.Errorf("unexpected invalid dialer")
	}
	conn, err := dialer(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	type activeConn struct {
		net.Conn
		a *activeTransport
	}
	return &activeConn{Conn: conn, a: a}, nil // keep reference alive
}

func (a *activeTransport) TLSClientConfig() *tls.Config {
	return a.val.rt.TLSClientConfig
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
		caData:             string(c.TLS.CAData),
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

	return k, true, nil
}
