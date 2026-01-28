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

package transport

import (
	"bytes"
	"net/http"
	"os"
	"sync"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/tools/metrics"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

var _ utilnet.RoundTripperWrapper = &atomicTransportHolder{}

var caRefreshDuration = 5 * time.Minute // TODO move to local var

// atomicTransportHolder holds a transport that can be atomically updated
// when CA files change, enabling graceful CA rotation without cache complexity
type atomicTransportHolder struct {
	caFile        string
	currentCAData []byte // Track the actual CA data currently in use
	// clock is used to allow for testing time-based logic.
	clock clock.Clock
	// mu covers transport and transportLastUpdated
	mu                   sync.RWMutex
	transport            *http.Transport
	transportLastChecked time.Time
}

func (h *atomicTransportHolder) RoundTrip(req *http.Request) (*http.Response, error) {
	return h.getTransport().RoundTrip(req)
}

func (h *atomicTransportHolder) WrappedRoundTripper() http.RoundTripper {
	return h.getTransport()
}

func (h *atomicTransportHolder) getTransport() *http.Transport {
	if tr := h.getTransportIfFresh(); tr != nil {
		return tr
	}
	return h.tryRefreshTransport()
}

func (h *atomicTransportHolder) getTransportIfFresh() *http.Transport {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.clock.Since(h.transportLastChecked) < caRefreshDuration {
		return h.transport
	}
	return nil
}

func (h *atomicTransportHolder) tryRefreshTransport() *http.Transport {
	h.mu.Lock()
	defer h.mu.Unlock()

	// If some other goroutine already checked/updated the CA
	if h.clock.Since(h.transportLastChecked) < caRefreshDuration {
		return h.transport
	}

	h.transportLastChecked = h.clock.Now()

	klog.V(4).InfoS("Checking CA file content", "caFile", h.caFile)

	// Load new CA data from file
	newCAData, err := os.ReadFile(h.caFile)
	// Return old transport on read error
	if err != nil {
		// TODO log err
		metrics.TransportCAReloads.Increment("failure", "read_error")
		return h.transport
	}

	if len(newCAData) == 0 || bytes.Equal(h.currentCAData, newCAData) {
		klog.V(4).InfoS("CA file unchanged or empty, skipping transport rotation", "caFile", h.caFile)
		metrics.TransportCAReloads.Increment("success", "unchanged")
		return h.transport
	}
	klog.V(4).InfoS("CA content changed, updating transport", "caFile", h.caFile)

	// Load new CA pool
	newCAs, err := rootCertPool(newCAData)
	// Return old transport on parse error
	if err != nil {
		metrics.TransportCAReloads.Increment("failure", "ca_parse_error")
		return h.transport
	}
	newTransport := h.transport.Clone()
	newTransport.TLSClientConfig.RootCAs = newCAs
	oldTransport := h.transport
	h.transport = newTransport
	// Update our tracking of current CA data
	h.currentCAData = newCAData

	// Close idle connections on the old transport to encourage migration
	oldTransport.CloseIdleConnections() // TODO close all?

	klog.V(4).InfoS("Transport updated for CA rotation", "caFile", h.caFile)
	metrics.TransportCAReloads.Increment("success", "updated")
	return h.transport
}

// newAtomicTransportHolder creates a new holder for CA file reloading scenarios
// TODO write assumptions about inputs
func newAtomicTransportHolder(caFile string, caData []byte, transport *http.Transport, c clock.Clock) *atomicTransportHolder {
	return &atomicTransportHolder{
		caFile:               caFile,
		currentCAData:        caData,
		clock:                c,
		transportLastChecked: c.Now(),
		transport:            transport,
	}
}
