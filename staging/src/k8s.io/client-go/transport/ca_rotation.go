/*
Copyright The Kubernetes Authors.

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
	"bytes"
	"context"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/tools/metrics"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

var _ utilnet.RoundTripperWrapper = &atomicTransportHolder{}

// atomicTransportHolder holds a transport that can be atomically updated
// when CA files change, enabling graceful CA rotation without cache complexity.
//
// When the GC feature gate is enabled, the holder is stored in the cache via
// weak.Pointer[atomicTransportHolder] and the inner *http.Transport is stored
// strongly.  This means:
//   - Holding the *atomicTransportHolder keeps the *http.Transport alive.
//   - Holding the *http.Transport (via unwrap) keeps only the transport alive
//     (the holder may be GC'd, but the transport's cleanup will handle eviction).
//   - When both the holder and all extracted *http.Transport references are gone,
//     the cleanup fires and the cache entry is evicted.
type atomicTransportHolder struct {
	skipReload    bool
	caFile        string
	currentCAData []byte // Track the actual CA data currently in use
	// clock and caRefreshDuration are used to allow for testing time-based logic.
	clock             clock.Clock
	caRefreshDuration time.Duration
	// onTransportCleanup is called when a *http.Transport is garbage collected.
	onTransportCleanup func()
	// onTransportCreated is called when a new *http.Transport is created
	// (initial creation and after CA rotation).
	onTransportCreated func()
	// mu covers transport and transportLastChecked
	mu                   sync.RWMutex
	transport            *http.Transport
	transportLastChecked time.Time
}

func (h *atomicTransportHolder) RoundTrip(req *http.Request) (*http.Response, error) {
	return h.getTransport(req.Context()).RoundTrip(req)
}

func (h *atomicTransportHolder) WrappedRoundTripper() http.RoundTripper {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.transport
}

func (h *atomicTransportHolder) getTransport(ctx context.Context) *http.Transport {
	if h.skipReload {
		return h.transport
	}

	if rt := h.getTransportIfFresh(); rt != nil {
		return rt
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.tryRefreshTransportLocked(ctx)
	return h.transport
}

func (h *atomicTransportHolder) getTransportIfFresh() *http.Transport {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.clock.Since(h.transportLastChecked) < h.caRefreshDuration {
		return h.transport
	}
	return nil
}

func (h *atomicTransportHolder) tryRefreshTransportLocked(ctx context.Context) {
	// If some other goroutine already checked/updated the CA
	if h.clock.Since(h.transportLastChecked) < h.caRefreshDuration {
		return
	}

	// only attempt CA reload once per caRefreshDuration, even if the reload fails
	h.transportLastChecked = h.clock.Now()

	logger := klog.FromContext(ctx).WithValues("caFile", h.caFile)

	logger.V(4).Info("Checking CA file content")

	// Load new CA data from file
	newCAData, err := os.ReadFile(h.caFile)
	// Return old transport on read error
	if err != nil {
		logger.Error(err, "Failed to read CA data from file")
		metrics.TransportCAReloads.Increment("failure", "read_error")
		return
	}

	if len(newCAData) == 0 {
		logger.Info("CA file empty, skipping transport rotation")
		metrics.TransportCAReloads.Increment("failure", "empty")
		return
	}

	if bytes.Equal(h.currentCAData, newCAData) {
		logger.V(4).Info("CA file unchanged, skipping transport rotation")
		metrics.TransportCAReloads.Increment("success", "unchanged")
		return
	}

	logger.V(4).Info("CA content changed, updating transport")

	// Load new CA pool
	newCAs, err := rootCertPool(newCAData)
	// Return old transport on parse error
	if err != nil {
		logger.Error(err, "Failed to parse CA data from file")
		metrics.TransportCAReloads.Increment("failure", "ca_parse_error")
		return
	}
	newTransport := h.transport.Clone()
	newTransport.TLSClientConfig.RootCAs = newCAs
	oldTransport := h.transport
	h.transport = newTransport
	// Update our tracking of current CA data
	h.currentCAData = newCAData

	// Register cleanup on the new transport so that if the holder is GC'd
	// (caller dropped it) and this transport is eventually also GC'd,
	// the cache entry will be evicted.
	h.registerTransportCleanup(newTransport)

	// Close idle connections on the old transport to encourage migration
	oldTransport.CloseIdleConnections()

	logger.V(4).Info("Transport updated for CA rotation")
	metrics.TransportCAReloads.Increment("success", "updated")
}

// registerTransportCleanup registers a runtime.AddCleanup on the given transport
// that will call the holder's cleanup function when the transport is garbage
// collected. This is safe to call multiple times for different transports
// (e.g. after CA rotation) — the cleanup function is responsible for checking
// whether the cache entry is still current before evicting.
func (h *atomicTransportHolder) registerTransportCleanup(transport *http.Transport) {
	h.onTransportCreated()
	runtime.AddCleanup(transport, func(cleanup func()) {
		cleanup()
	}, h.onTransportCleanup)
}

// newAtomicTransportHolder creates a new holder for CA file reloading scenarios.
func newAtomicTransportHolder(caFile string, caData []byte, transport *http.Transport, onTransportCleanup, onTransportCreated func()) *atomicTransportHolder {
	c := clock.RealClock{}
	h := &atomicTransportHolder{
		caFile:               caFile,
		currentCAData:        caData,
		clock:                c,
		caRefreshDuration:    5 * time.Minute,
		onTransportCleanup:   onTransportCleanup,
		onTransportCreated:   onTransportCreated,
		transport:            transport,
		transportLastChecked: c.Now(),
	}
	h.registerTransportCleanup(transport)
	return h
}

func newAtomicTransportHolderWithoutReload(transport *http.Transport, onTransportCleanup, onTransportCreated func()) *atomicTransportHolder {
	h := &atomicTransportHolder{
		skipReload:         true,
		onTransportCleanup: onTransportCleanup,
		onTransportCreated: onTransportCreated,
		transport:          transport,
	}
	h.registerTransportCleanup(transport)
	return h
}
