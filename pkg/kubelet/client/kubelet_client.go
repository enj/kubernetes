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
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

type reqCtxKeyType int

const (
	reqTLSConnKey reqCtxKeyType = iota
	reqCommonNameKey
)

func withTLSConn(ctx context.Context, tlsConn *tls.Conn) context.Context {
	return context.WithValue(ctx, reqTLSConnKey, tlsConn)
}

func tlsConnFrom(ctx context.Context) (*tls.Conn, bool) {
	tlsConn, ok := ctx.Value(reqTLSConnKey).(*tls.Conn)
	return tlsConn, ok
}

func withCommonName(ctx context.Context, commonName string) context.Context {
	return context.WithValue(ctx, reqCommonNameKey, commonName)
}

func commonNameFrom(ctx context.Context) (string, bool) {
	commonName, ok := ctx.Value(reqCommonNameKey).(string)
	return commonName, ok
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
		// always bust the client-go TLS cache instead of only when KubeletClientConfig.Lookup is set.
		// this allows us to safely mutate the underlying *http.Transport in mutateTransportToValidateNodeName.
		// note that we do not need the client-go TLS cache since we make and re-use a small number of transports.
		// TODO add unit test
		//  1. unique transport per call for same inputs
		//  2. unwrapping still works at high log levels when the transport is actually wrapped
		Proxy: http.ProxyFromEnvironment,
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
	if config.TLSClientConfig.ValidateNodeName {
		if err := mutateTransportToValidateNodeName(transport); err != nil {
			return nil, err
		}
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
		rt = &withValueRoundTripper{delegate: rt, with: func(ctx context.Context) context.Context {
			return withCommonName(ctx, "system:node:"+string(nodeName))
		}}
	}

	return &ConnectionInfo{
		Scheme:                         k.scheme,
		Hostname:                       hostname,
		Port:                           portStr,
		Transport:                      rt,
		InsecureSkipTLSVerifyTransport: k.insecureSkipTLSVerifyTransport,
	}, nil
}

var _ utilnet.RoundTripperWrapper = &validateNodeNameRoundTripper{}

type validateNodeNameRoundTripper struct {
	delegate http.RoundTripper
}

func (v *validateNodeNameRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return v.delegate
}

func (v *validateNodeNameRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	tlsConn, ok := tlsConnFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to get TLS conn from context")
	}

	commonName, ok := commonNameFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to get TLS conn from context")
	}

	if err := validateNodeName(tlsConn.ConnectionState(), commonName); err != nil {
		return nil, err
	}

	return v.delegate.RoundTrip(req)
}

var _ http2.ClientConnPool = &validateNodeNameClientConnPool{}

type validateNodeNameClientConnPool struct {
	delegate http2.ClientConnPool
}

func (v *validateNodeNameClientConnPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	commonName, ok := commonNameFrom(req.Context())
	if !ok {
		return nil, fmt.Errorf("failed to get TLS conn from context")
	}

	clientConn, err := v.delegate.GetClientConn(req, addr)
	if err != nil {
		return nil, err
	}

	if err := validateNodeName(clientConn.State(), commonName); err != nil {
		_, _ = clientConn.RoundTrip(new(http.Request)) // release the stream reservation per ClientConnPool docs
		return nil, err
	}

	return clientConn, nil
}

func (v *validateNodeNameClientConnPool) MarkDead(clientConn *http2.ClientConn) {
	v.delegate.MarkDead(clientConn)
}

// add the extra kubelet common name check based on ValidateKubeletServingCSR
func validateNodeName(cs tls.ConnectionState, commonName string) error {
	leaf := cs.PeerCertificates[0]
	if leaf.Subject.CommonName != commonName {
		return fmt.Errorf("invalid node serving cert common name; expected %q, got %q", commonName, leaf.Subject.CommonName)
	}
	if !slices.Equal(leaf.Subject.Organization, nodeOrganization) {
		return fmt.Errorf("invalid node serving cert organization; expected %q, got %q", nodeOrganization, leaf.Subject.Organization)
	}
	return nil
}

var _ utilnet.RoundTripperWrapper = &withValueRoundTripper{}

type withValueRoundTripper struct {
	delegate http.RoundTripper
	with     func(context.Context) context.Context
}

func (w *withValueRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return w.delegate
}

func (w *withValueRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := w.with(req.Context())
	req = req.WithContext(ctx)
	return w.delegate.RoundTrip(req)
}

var nodeOrganization = []string{user.NodesGroup}

func mutateTransportToValidateNodeName(baseRT http.RoundTripper) error {
	rt, err := httpTransportFor(baseRT)
	if err != nil {
		return fmt.Errorf("failed to get *http.Transport for transport: %w", err)
	}

	const h1 = "http/1.1"

	if rt.DialTLSContext != nil || rt.TLSNextProto[h1] != nil || rt.TLSNextProto[http2.NextProtoTLS] == nil {
		return fmt.Errorf("*http.Transport has invalid state: %#v", rt) // sanity check client-go internals that we rely on
	}

	h1NoDialRT := rt.Clone()
	h1NoDialRT.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		tlsConn, ok := tlsConnFrom(ctx)
		if !ok {
			return nil, fmt.Errorf("failed to get TLS conn from context")
		}
		return &hideTLSConn{Conn: tlsConn}, nil
	}
	h1AlwaysValidateRT := &validateNodeNameRoundTripper{delegate: h1NoDialRT}

	// mutate the underlying *http.Transport in-place
	rt.TLSNextProto[h1] = func(_ string, tlsConn *tls.Conn) http.RoundTripper {
		return &withValueRoundTripper{delegate: h1AlwaysValidateRT, with: func(ctx context.Context) context.Context {
			// note that this assumes that this TLS conn is always used, which is true for http1 but not for http2
			// TODO make sure this does not leak TLS conn
			return withTLSConn(ctx, tlsConn)
		}}
	}

	var h2Lock sync.Mutex
	h2Alpn := rt.TLSNextProto[http2.NextProtoTLS]
	rt.TLSNextProto[http2.NextProtoTLS] = func(authority string, tlsConn *tls.Conn) http.RoundTripper {
		h2Lock.Lock()
		defer h2Lock.Unlock()

		h2Rt := h2Alpn(authority, tlsConn)
		h2Transport, ok := h2Rt.(*http2.Transport)
		if !ok || h2Transport.ConnPool == nil {
			return erringRoundTripper{err: fmt.Errorf("invalid *http2.Transport: %T", h2Rt)}
		}

		h2Transport.ConnPool
	}

	// TODO this check enforces that proxy URL is not set, does that make sense?
	// TODO maybe we should overwrite the proxy func to always return nil?  http.ProxyURL(nil)
	return nil
}

func httpTransportFor(rt http.RoundTripper) (*http.Transport, error) {
	switch t := rt.(type) {
	case *http.Transport:
		return t, nil
	case utilnet.RoundTripperWrapper: // TODO see if we can add a unit test to enforce that all http.RoundTripper in k/k implement this
		return httpTransportFor(t.WrappedRoundTripper())
	default:
		return nil, fmt.Errorf("unknown transport type: %T", t)
	}
}

type hideTLSConn struct {
	net.Conn
}

type erringRoundTripper struct{ err error }

func (rt erringRoundTripper) RoundTripErr() error                             { return rt.err }
func (rt erringRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, rt.err }
