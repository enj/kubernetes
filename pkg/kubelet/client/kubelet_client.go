/*
Copyright 2014 The Kubernetes Authors.

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

package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server/egressselector"
	"k8s.io/client-go/transport"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
)

// KubeletClientConfig defines config parameters for the kubelet client
type KubeletClientConfig struct {
	// Port specifies the default port - used if no information about Kubelet port can be found in Node.NodeStatus.DaemonEndpoints.
	Port uint

	// ReadOnlyPort specifies the Port for ReadOnly communications.
	ReadOnlyPort uint

	// PreferredAddressTypes - used to select an address from Node.NodeStatus.Addresses
	PreferredAddressTypes []string

	// TLSClientConfig contains settings to enable transport layer security
	TLSClientConfig KubeletTLSConfig

	// HTTPTimeout is used by the client to timeout http requests to Kubelet.
	HTTPTimeout time.Duration

	// Lookup will give us a dialer if the egress selector is configured for it
	Lookup egressselector.Lookup
}

type KubeletTLSConfig struct {
	// Server requires TLS client certificate authentication
	CertFile string
	// Server requires TLS client certificate authentication
	KeyFile string
	// Trusted root certificates for server
	CAFile string
	// Check that the kubelet's serving certificate common name matches the name of the kubelet
	ValidateNodeName bool
}

// ConnectionInfo provides the information needed to connect to a kubelet
type ConnectionInfo struct {
	Scheme                         string
	Hostname                       string
	Port                           string
	Transport                      http.RoundTripper
	InsecureSkipTLSVerifyTransport http.RoundTripper
}

// ConnectionInfoGetter provides ConnectionInfo for the kubelet running on a named node
type ConnectionInfoGetter interface {
	GetConnectionInfo(ctx context.Context, nodeName types.NodeName) (*ConnectionInfo, error)
}

type dialRewrite struct {
	cn               string
	cnWithPort       string
	hostname         string
	hostnameWithPort string
}

type dialRewriteKeyType int

const dialRewriteKey dialRewriteKeyType = iota

func withDialRewrite(ctx context.Context, dr dialRewrite) context.Context {
	return context.WithValue(ctx, dialRewriteKey, dr)
}

func dialRewriteFrom(ctx context.Context) (dialRewrite, bool) {
	dr, ok := ctx.Value(dialRewriteKey).(dialRewrite)
	return dr, ok
}

// MakeTransport creates a secure RoundTripper for HTTP Transport.
func MakeTransport(config *KubeletClientConfig) (http.RoundTripper, error) {
	return makeTransport(config, false)
}

// MakeInsecureTransport creates an insecure RoundTripper for HTTP Transport.
func MakeInsecureTransport(config *KubeletClientConfig) (http.RoundTripper, error) {
	return makeTransport(config, true)
}

// makeTransport creates a RoundTripper for HTTP Transport.
func makeTransport(config *KubeletClientConfig, insecureSkipTLSVerify bool) (http.RoundTripper, error) {
	// do the insecureSkipTLSVerify on the pre-transport *before* we go get a potentially cached connection.
	// transportConfig always produces a new struct pointer.
	transportConfig := config.transportConfig()
	if insecureSkipTLSVerify {
		transportConfig.TLS.Insecure = true
		transportConfig.TLS.CAFile = "" // we are only using files so we can ignore CAData
	}

	if config.Lookup != nil {
		// Assuming EgressSelector if SSHTunnel is not turned on.
		// We will not get a dialer if egress selector is disabled.
		networkContext := egressselector.Cluster.AsNetworkContext()
		dialer, err := config.Lookup(networkContext)
		if err != nil {
			return nil, fmt.Errorf("failed to get context dialer for 'cluster': got %v", err)
		}
		if dialer != nil {
			transportConfig.DialHolder = &transport.DialHolder{Dial: dialer}
		}
	}
	return transport.New(transportConfig)
}

// transportConfig converts a client config to an appropriate transport config.
func (c *KubeletClientConfig) transportConfig() *transport.Config {
	cfg := &transport.Config{
		TLS: transport.TLSConfig{
			CAFile:   c.TLSClientConfig.CAFile,
			CertFile: c.TLSClientConfig.CertFile,
			KeyFile:  c.TLSClientConfig.KeyFile,
			// transport.loadTLSFiles would set this to true because we are only using files
			// it is clearer to set it explicitly here so we remember that this is happening
			ReloadTLSFiles: true,
		},
	}
	if !cfg.HasCA() {
		cfg.TLS.Insecure = true
	}
	return cfg
}

// NodeGetter defines an interface for looking up a node by name
type NodeGetter interface {
	Get(ctx context.Context, name string, options metav1.GetOptions) (*v1.Node, error)
}

// NodeGetterFunc allows implementing NodeGetter with a function
type NodeGetterFunc func(ctx context.Context, name string, options metav1.GetOptions) (*v1.Node, error)

// Get fetches information via NodeGetterFunc.
func (f NodeGetterFunc) Get(ctx context.Context, name string, options metav1.GetOptions) (*v1.Node, error) {
	return f(ctx, name, options)
}

// NodeConnectionInfoGetter obtains connection info from the status of a Node API object
type NodeConnectionInfoGetter struct {
	// nodes is used to look up Node objects
	nodes NodeGetter
	// scheme is the scheme to use to connect to all kubelets
	scheme string
	// defaultPort is the port to use if no Kubelet endpoint port is recorded in the node status
	defaultPort int
	// transport is the transport to use to send a request to all kubelets
	transport http.RoundTripper
	// proxy is proxy func associated with transport
	proxy func(*http.Request) (*url.URL, error)
	// check that the kubelet's serving certificate common name matches the name of the kubelet
	validateNodeName bool
	// insecureSkipTLSVerifyTransport is the transport to use if the kube-apiserver wants to skip verifying the TLS certificate of the kubelet
	insecureSkipTLSVerifyTransport http.RoundTripper
	// preferredAddressTypes specifies the preferred order to use to find a node address
	preferredAddressTypes []v1.NodeAddressType
}

// NewNodeConnectionInfoGetter creates a new NodeConnectionInfoGetter.
func NewNodeConnectionInfoGetter(nodes NodeGetter, config KubeletClientConfig) (ConnectionInfoGetter, error) {
	transport, err := MakeTransport(&config)
	if err != nil {
		return nil, err
	}
	proxy, err := proxyFor(transport)
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy for transport: %w", err)
	}
	if config.TLSClientConfig.ValidateNodeName {
		rt, err := httpTransportFor(transport)
		if err != nil {
			return nil, fmt.Errorf("failed to get *http.Transport for transport: %w", err)
		}
		if rt.DialTLSContext != nil || rt.DialContext == nil || rt.TLSClientConfig == nil {
			return nil, fmt.Errorf("*http.Transport has invalid state")
		}
		rt = rt.Clone() // so we can mutate it safely
		rt.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, fmt.Errorf("only tcp connections are supported")
			}
			dr, ok := dialRewriteFrom(ctx)
			if !ok {
				return nil, fmt.Errorf("failed to get dial rewrite from context")
			}
			if address != dr.cnWithPort {
				return nil, fmt.Errorf("rewrite of %q->%q failed, got unexpected address %q", dr.cnWithPort, dr.hostnameWithPort, address)
			}
			rawConn, err := rt.DialContext(ctx, "tcp", dr.hostnameWithPort)
			if err != nil {
				return nil, fmt.Errorf("failed to make TCP connection: %w", err)
			}
			tlsConfig := rt.TLSClientConfig.Clone()
			tlsConfig.ServerName = dr.hostname // maintain the existing SAN check
			tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
				leaf := cs.PeerCertificates[0]
				if leaf.Subject.CommonName != dr.cn {
					return fmt.Errorf("invalid node name; expected %q, got %q", dr.cn, leaf.Subject.CommonName)
				}
				if !slices.Contains(leaf.Subject.Organization, user.NodesGroup) {
					return fmt.Errorf("invalid node groups; expected to include %q, got %q", user.NodesGroup, leaf.Subject.Organization)
				}
				return nil
			}
			return tls.Client(rawConn, tlsConfig), nil // TODO fix handshake logic to match std lib
		}
		transport = rt
	}

	insecureSkipTLSVerifyTransport, err := MakeInsecureTransport(&config)
	if err != nil {
		return nil, err
	}

	types := []v1.NodeAddressType{}
	for _, t := range config.PreferredAddressTypes {
		types = append(types, v1.NodeAddressType(t))
	}

	return &NodeConnectionInfoGetter{
		nodes:                          nodes,
		scheme:                         "https",
		defaultPort:                    int(config.Port),
		transport:                      transport,
		proxy:                          proxy,
		validateNodeName:               config.TLSClientConfig.ValidateNodeName,
		insecureSkipTLSVerifyTransport: insecureSkipTLSVerifyTransport,

		preferredAddressTypes: types,
	}, nil
}

// GetConnectionInfo retrieves connection info from the status of a Node API object.
func (k *NodeConnectionInfoGetter) GetConnectionInfo(ctx context.Context, nodeName types.NodeName) (*ConnectionInfo, error) {
	node, err := k.nodes.Get(ctx, string(nodeName), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// Find a kubelet-reported address, using preferred address type
	hostname, err := nodeutil.GetPreferredNodeAddress(node, k.preferredAddressTypes)
	if err != nil {
		return nil, err
	}

	// Use the kubelet-reported port, if present
	port := int(node.Status.DaemonEndpoints.KubeletEndpoint.Port)
	if port <= 0 {
		port = k.defaultPort
	}
	portStr := strconv.Itoa(port)

	rt := k.transport
	if k.validateNodeName {
		cn := "system:node:" + string(nodeName)
		rt = &validateNodeNameRoundTripper{
			nodeName: nodeName,
			delegate: rt,
			proxy:    k.proxy,
			dr: dialRewrite{
				cn:               cn,
				cnWithPort:       net.JoinHostPort(cn, portStr),
				hostname:         hostname,
				hostnameWithPort: net.JoinHostPort(hostname, portStr),
			},
		}
	}

	return &ConnectionInfo{
		Scheme:                         k.scheme,
		Hostname:                       hostname,
		Port:                           portStr,
		Transport:                      rt,
		InsecureSkipTLSVerifyTransport: k.insecureSkipTLSVerifyTransport,
	}, nil
}

var errNodeNameValidationSkipped = fmt.Errorf("node name was not validated")

var _ utilnet.RoundTripperWrapper = &validateNodeNameRoundTripper{}

type validateNodeNameRoundTripper struct {
	nodeName types.NodeName
	delegate http.RoundTripper
	proxy    func(*http.Request) (*url.URL, error)
	dr       dialRewrite
}

func (r *validateNodeNameRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return r.delegate
}

func (r *validateNodeNameRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf(`node name %q must use scheme "https", got %q`, r.nodeName, req.URL.Scheme)
	}
	if req.URL.Host != r.dr.hostnameWithPort {
		return nil, fmt.Errorf("node name %q must use host %q, got %q", r.nodeName, r.dr.hostnameWithPort, req.URL.Host)
	}
	if len(req.Host) > 0 && req.Host != r.dr.hostnameWithPort {
		return nil, fmt.Errorf("node name %q must use host %q, got %q", r.nodeName, r.dr.hostnameWithPort, req.Host)
	}

	ctx := withDialRewrite(req.Context(), r.dr)
	req = req.Clone(ctx)       // so we can mutate the request URL
	req.Host = r.dr.cnWithPort // TODO should we set this to the empty string?
	req.URL.Host = r.dr.cnWithPort

	resp, err := r.delegate.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// check the actual response TLS connection state before returning it
	// this means that we could make a "bad" request to the kubelet, but at least we will not forward it to the client
	if err := r.validateNodeNameConnectionState(resp.TLS); err != nil {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf(`FAIL TEST IF SEEN: node name %q validation failed: %w`, r.nodeName, err)
	}

	return resp, nil
}

func (r *validateNodeNameRoundTripper) probeHostTLS(baseReq *http.Request) (rtErr error) {
	ctx, cancel := context.WithCancelCause(baseReq.Context())
	defer cancel(nil)

	req, err := r.buildProbeRequest(baseReq)
	if err != nil {
		return err
	}

	var (
		lock      sync.Mutex // trace functions may be called concurrently from different goroutines
		failedErr error
		validated bool
	)
	defer func() {
		lock.Lock()
		defer lock.Unlock()

		if !validated && failedErr == nil {
			rtErr = newAggregateWithCleaning(errNodeNameValidationSkipped, rtErr)
		}

		if failedErr != nil && failedErr != rtErr {
			rtErr = newAggregateWithCleaning(failedErr, rtErr)
		}
	}()

	// TODO decide if we want to use tracing or just response.TLS
	trace := &httptrace.ClientTrace{
		// the easiest thing would be to panic here and while that would likely work today because everything is
		// within the same goroutine, the docs for httptrace state that different goroutines may be used meaning
		// that in the future such a panic could cause the entire process to terminate
		GotConn: func(connInfo httptrace.GotConnInfo) {
			lock.Lock()
			defer lock.Unlock()

			if failedErr != nil {
				return
			}

			if err := r.validateNodeName(connInfo.Conn); err != nil {
				failedErr = err // TODO decide on klog / audit log / metrics around this
				cancel(err)     // best effort request cancellation

				// make it impossible for the request to be sent
				// TODO decide if making the request invalid like this makes sense
				invalidRequest := new(http.Request).WithContext(req.Context())
				*req = *invalidRequest
				return
			}

			validated = true // make sure the validation is actually called
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(ctx, trace)) // WithClientTrace automatically composes with any existing trace
	resp, err := r.delegate.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	return err
}

func (r *validateNodeNameRoundTripper) buildProbeRequest(baseReq *http.Request) (*http.Request, error) {
	cm, err := connectMethodForRequest(baseReq, r.proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to determine connect method for request to node %q: %w", r.nodeName, err)
	}
	cmk := cm.key()
	if len(cmk.proxy) != 0 || cmk.onlyH1 {
		return nil, fmt.Errorf("unhandled connect method key: %#v", cmk) // TODO handle these as well
	}
	if cmk.scheme != "https" {
		return nil, fmt.Errorf("unhandled connect method scheme: %q", cmk.scheme)
	}
	// TODO add single flight logic
	// TODO maybe use MethodOptions instead?
	// TODO maybe add size limited LRU caching with a short TTL?
	// TODO determine if the assumptions we are making about "TLS overlap" are safe
	req, err := http.NewRequestWithContext(baseReq.Context(), http.MethodHead, (&url.URL{Scheme: "https", Host: cmk.addr}).String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build probe request to host %q: %w", cmk.addr, err)
	}
	return req, nil
}

func (r *validateNodeNameRoundTripper) validateNodeName(conn net.Conn) error {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return fmt.Errorf("invalid connection type; expected tls.Conn, got %T", conn)
	}
	cs := tlsConn.ConnectionState()
	return r.validateNodeNameConnectionState(&cs)
}

func (r *validateNodeNameRoundTripper) validateNodeNameConnectionState(cs *tls.ConnectionState) error {
	if cs == nil {
		return fmt.Errorf("invalid nil connection state")
	}
	if !cs.HandshakeComplete {
		return fmt.Errorf("invalid connection state; handshake not complete")
	}
	leaf := cs.PeerCertificates[0]
	if expectedNodeName := "system:node:" + string(r.nodeName); leaf.Subject.CommonName != expectedNodeName {
		return fmt.Errorf("invalid node name; expected %q, got %q", expectedNodeName, leaf.Subject.CommonName)
	}
	if !slices.Contains(leaf.Subject.Organization, user.NodesGroup) {
		return fmt.Errorf("invalid node groups; expected to include %q, got %q", user.NodesGroup, leaf.Subject.Organization)
	}
	return nil
}

func newAggregateWithCleaning(errs ...error) error {
	return utilerrors.Reduce(utilerrors.FilterOut(utilerrors.NewAggregate(errs), func(err error) bool { return err == context.Canceled }))
}

func proxyFor(rt http.RoundTripper) (func(*http.Request) (*url.URL, error), error) {
	switch t := rt.(type) {
	case *http.Transport:
		return t.Proxy, nil
	case utilnet.RoundTripperWrapper:
		return proxyFor(t.WrappedRoundTripper())
	default:
		return nil, fmt.Errorf("unknown transport type: %T", t)
	}
}

func httpTransportFor(rt http.RoundTripper) (*http.Transport, error) {
	switch t := rt.(type) {
	case *http.Transport:
		return t, nil
	case utilnet.RoundTripperWrapper:
		return httpTransportFor(t.WrappedRoundTripper())
	default:
		return nil, fmt.Errorf("unknown transport type: %T", t)
	}
}
