/*
Copyright 2018 The Kubernetes Authors.

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

package exec

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/term"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
	"k8s.io/apimachinery/pkg/util/clock"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	"k8s.io/client-go/pkg/apis/clientauthentication/install"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1alpha1 "k8s.io/client-go/pkg/apis/clientauthentication/v1alpha1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/metrics"
	"k8s.io/client-go/transport"
	"k8s.io/client-go/util/connrotation"
	"k8s.io/klog/v2"
)

const execInfoEnv = "KUBERNETES_EXEC_INFO"
const installHintVerboseHelp = `

It looks like you are trying to use a client-go credential plugin that is not installed.

To learn more about this feature, consult the documentation available at:
      https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins`

var codecs serializer.CodecFactory
var framer runtime.Framer

func init() {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	codecs = serializer.NewCodecFactory(scheme)

	var err error
	negotiator := runtime.NewClientNegotiator(codecs, schema.GroupVersion{ /* unused */ })
	_, _, framer, err = negotiator.StreamDecoder(runtime.ContentTypeJSON, nil)
	utilruntime.Must(err)
}

var (
	// Since transports can be constantly re-initialized by programs like kubectl,
	// keep a cache of initialized authenticators keyed by a hash of their config.
	globalCache = newCache()
	// The list of API versions we accept.
	apiVersions = map[string]schema.GroupVersion{
		clientauthenticationv1alpha1.SchemeGroupVersion.String(): clientauthenticationv1alpha1.SchemeGroupVersion,
		clientauthenticationv1beta1.SchemeGroupVersion.String():  clientauthenticationv1beta1.SchemeGroupVersion,
		clientauthenticationv1.SchemeGroupVersion.String():       clientauthenticationv1.SchemeGroupVersion,
	}
)

func newCache() *cache {
	return &cache{m: make(map[string]*Authenticator)}
}

var spewConfig = &spew.ConfigState{DisableMethods: true, Indent: " "}

func cacheKey(conf *api.ExecConfig, cluster *clientauthentication.Cluster) string {
	key := struct {
		conf    *api.ExecConfig
		cluster *clientauthentication.Cluster
	}{
		conf:    conf,
		cluster: cluster,
	}
	return spewConfig.Sprint(key)
}

type cache struct {
	mu sync.Mutex
	m  map[string]*Authenticator
}

func (c *cache) get(s string) (*Authenticator, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.m[s]
	return a, ok
}

// put inserts an authenticator into the cache. If an authenticator is already
// associated with the key, the first one is returned instead.
func (c *cache) put(s string, a *Authenticator) *Authenticator {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.m[s]
	if ok {
		return existing
	}
	c.m[s] = a
	return a
}

// sometimes rate limits how often a function f() is called. Specifically, Do()
// will run the provided function f() up to threshold times every interval
// duration.
type sometimes struct {
	threshold int
	interval  time.Duration

	clock clock.Clock
	mu    sync.Mutex

	count  int       // times we have called f() in this window
	window time.Time // beginning of current window of length interval
}

func (s *sometimes) Do(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	if s.window.IsZero() {
		s.window = now
	}

	// If we are no longer in our saved time window, then we get to reset our run
	// count back to 0 and start increasing towards the threshold again.
	if inWindow := now.Sub(s.window) < s.interval; !inWindow {
		s.window = now
		s.count = 0
	}

	// If we have not run the function more than threshold times in this current
	// time window, we get to run it now!
	if underThreshold := s.count < s.threshold; underThreshold {
		s.count++
		f()
	}
}

// GetAuthenticator returns an exec-based plugin for providing client credentials.
func GetAuthenticator(config *api.ExecConfig, cluster *clientauthentication.Cluster) (*Authenticator, error) {
	return newAuthenticator(globalCache, term.IsTerminal, config, cluster)
}

func newAuthenticator(c *cache, isTerminalFunc func(int) bool, config *api.ExecConfig, cluster *clientauthentication.Cluster) (*Authenticator, error) {
	key := cacheKey(config, cluster)
	if a, ok := c.get(key); ok {
		return a, nil
	}

	gv, ok := apiVersions[config.APIVersion]
	if !ok {
		return nil, fmt.Errorf("exec plugin: invalid apiVersion %q", config.APIVersion)
	}

	clusterURL, err := url.Parse(cluster.Server)
	if err != nil {
		return nil, fmt.Errorf("exec plugin: failed to parse cluster URL %q: %w", cluster.Server, err)
	}
	clusterPath := clusterURL.Path
	if !strings.HasSuffix(clusterPath, "/") {
		clusterPath += "/"
	}
	var clusterCA *x509.CertPool
	if len(cluster.CertificateAuthorityData) > 0 {
		clusterCA = x509.NewCertPool()
		if ok := clusterCA.AppendCertsFromPEM(cluster.CertificateAuthorityData); !ok {
			return nil, errors.New("invalid server CA data")
		}
	}
	clusterProxy := utilnet.NewProxierWithNoProxyCIDR(http.ProxyFromEnvironment)
	if len(cluster.ProxyURL) > 0 {
		proxyURL, err := url.Parse(cluster.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("exec plugin: failed to parse cluster proxy URL %q: %w", cluster.ProxyURL, err)
		}
		clusterProxy = http.ProxyURL(proxyURL)
	}

	connTracker := connrotation.NewConnectionTracker()
	defaultDialer := connrotation.NewDialerWithTracker(
		(&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		connTracker,
	)

	a := &Authenticator{
		cmd:                config.Command,
		args:               config.Args,
		group:              gv,
		cluster:            cluster,
		clusterCA:          clusterCA,
		clusterProxy:       clusterProxy,
		clusterPath:        clusterPath,
		provideClusterInfo: config.ProvideClusterInfo,

		installHint: config.InstallHint,
		sometimes: &sometimes{
			threshold: 10,
			interval:  time.Hour,
			clock:     clock.RealClock{},
		},

		stdin:           os.Stdin,
		stderr:          os.Stderr,
		interactiveFunc: func() (bool, error) { return isInteractive(isTerminalFunc, config) },
		now:             time.Now,
		environ:         os.Environ,
		callsMetric:     metrics.ExecPluginCalls,

		defaultDialer: defaultDialer,
		connTracker:   connTracker,
	}

	for _, env := range config.Env {
		a.env = append(a.env, env.Name+"="+env.Value)
	}

	return c.put(key, a), nil
}

func isInteractive(isTerminalFunc func(int) bool, config *api.ExecConfig) (bool, error) {
	var shouldBeInteractive bool
	switch config.InteractiveMode {
	case api.NeverExecInteractiveMode:
		shouldBeInteractive = false
	case api.IfAvailableExecInteractiveMode:
		shouldBeInteractive = !config.StdinUnavailable && isTerminalFunc(int(os.Stdin.Fd()))
	case api.AlwaysExecInteractiveMode:
		if !isTerminalFunc(int(os.Stdin.Fd())) {
			return false, errors.New("standard input is not a terminal")
		}
		if config.StdinUnavailable {
			suffix := ""
			if len(config.StdinUnavailableMessage) > 0 {
				// only print extra ": <message>" if the user actually specified a message
				suffix = fmt.Sprintf(": %s", config.StdinUnavailableMessage)
			}
			return false, fmt.Errorf("standard input is unavailable%s", suffix)
		}
		shouldBeInteractive = true
	default:
		return false, fmt.Errorf("unknown interactiveMode: %q", config.InteractiveMode)
	}

	return shouldBeInteractive, nil
}

// Authenticator is a client credential provider that rotates credentials by executing a plugin.
// The plugin input and output are defined by the API group client.authentication.k8s.io.
type Authenticator struct {
	// Set by the config
	cmd                string
	args               []string
	group              schema.GroupVersion
	env                []string
	cluster            *clientauthentication.Cluster
	clusterCA          *x509.CertPool
	clusterProxy       func(*http.Request) (*url.URL, error)
	clusterPath        string
	provideClusterInfo bool

	// Used to avoid log spew by rate limiting install hint printing. We didn't do
	// this by interval based rate limiting alone since that way may have prevented
	// the install hint from showing up for kubectl users.
	sometimes   *sometimes
	installHint string

	// Stubbable for testing
	stdin           io.Reader
	stderr          io.Writer
	interactiveFunc func() (bool, error)
	now             func() time.Time
	environ         func() []string
	callsMetric     metrics.CallsMetric

	// defaultDialer is used for clients which don't specify a custom dialer
	defaultDialer *connrotation.Dialer
	// connTracker tracks all connections opened that we need to close when rotating a client certificate
	connTracker *connrotation.ConnectionTracker

	// Cached results.
	//
	// The mutex also guards calling the plugin. Since the plugin could be
	// interactive we want to make sure it's only called once.
	mu          sync.Mutex
	cachedCreds *credentials
	exp         time.Time
	proxyCertUsed,
	proxyCertFailed bool
}

type credentials struct {
	token string           `datapolicy:"token"`
	cert  *tls.Certificate `datapolicy:"secret-key"`

	proxyConfig *proxyConfig
}

type proxyConfig struct {
	port int32
	ca   *x509.CertPool
}

// UpdateTransportConfig updates the transport.Config to use credentials
// returned by the plugin.
func (a *Authenticator) UpdateTransportConfig(c *transport.Config) error {
	// If a bearer token is present in the request - avoid the GetCert callback when
	// setting up the transport, as that triggers the exec action if the server is
	// also configured to allow client certificates for authentication. For requests
	// like "kubectl get --token (token) pods" we should assume the intention is to
	// use the provided token for authentication. The same can be said for when the
	// user specifies basic auth.
	if c.HasTokenAuth() || c.HasBasicAuth() {
		return nil
	}

	c.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &roundTripper{a: a, base: rt}
	})

	if c.TLS.GetCert != nil {
		return errors.New("can't add TLS certificate callback: transport.Config.TLS.GetCert already set")
	}
	c.TLS.GetCert = a.cert

	var d *connrotation.Dialer
	if c.Dial != nil {
		// if c has a custom dialer, we have to wrap it
		d = connrotation.NewDialerWithTracker(c.Dial, a.connTracker)
	} else {
		d = a.defaultDialer
	}

	c.Dial = d.DialContext

	c.Proxy = a.proxy

	if c.TLS.GetCA != nil {
		return errors.New("cannot add TLS root CA callback: transport.Config.TLS.GetCA already set")
	}
	c.TLS.GetCA = a.ca
	// make sure our ca func gets called
	c.TLS.CAFile = ""
	c.TLS.CAData = nil

	return nil
}

type roundTripper struct {
	a    *Authenticator
	base http.RoundTripper
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// If a user has already set credentials, use that. This makes commands like
	// "kubectl get --token (token) pods" work.
	if req.Header.Get("Authorization") != "" {
		return r.base.RoundTrip(req)
	}

	if r.a.getProxyCertFailed() {
		return nil, errors.New("exec plugin proxy short circuit: did not request client certificate for mTLS")
	}

	creds, err := r.a.getCreds()
	if err != nil {
		return nil, fmt.Errorf("getting credentials: %v", err)
	}
	if creds.token != "" {
		req.Header.Set("Authorization", "Bearer "+creds.token)
	}

	if creds.proxyConfig != nil {
		klog.Errorf("PROXY override to %d", creds.proxyConfig.port)

		req.URL.Scheme = "https"
		req.URL.Host = "127.0.0.1:" + strconv.Itoa(int(creds.proxyConfig.port))

		if len(r.a.clusterPath) != 0 {
			path := req.URL.Path
			path = "/" + strings.TrimPrefix(path, r.a.clusterPath)
			req.URL.Path = path
		}
	}

	res, err := r.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// after the fact verification is meh but at least it prevents real usage of a broken proxy
	if creds.proxyConfig != nil && !r.a.getProxyCertUsed() {
		r.a.setProxyCertFailed()
		return nil, errors.New("exec plugin proxy did not request client certificate for mTLS")
	}

	if res.StatusCode == http.StatusUnauthorized {
		resp := &clientauthentication.Response{
			Header: res.Header,
			Code:   int32(res.StatusCode),
		}
		if err := r.a.maybeRefreshCreds(creds, resp); err != nil {
			klog.Errorf("refreshing credentials: %v", err)
		}
	}
	return res, nil
}

func (a *Authenticator) credsExpired() bool {
	if a.exp.IsZero() {
		return false
	}
	return a.now().After(a.exp)
}

func (a *Authenticator) cert(acceptableCAs [][]byte) (*tls.Certificate, error) {
	creds, err := a.getCreds()
	if err != nil {
		return nil, err
	}

	klog.Errorf("SAW acceptableCAs %d", len(acceptableCAs))

	// TODO make sure it is the same CA as the the proxy config CA, if given
	if creds.proxyConfig != nil {
		if len(acceptableCAs) == 0 {
			return nil, errors.New("exec plugin proxy did not request client certificate for mTLS")
		}

		if creds.cert != nil {
			a.setProxyCertUsed()
		}
	}

	return creds.cert, nil
}

func (a *Authenticator) ca() (*x509.CertPool, error) {
	creds, err := a.getCreds()
	if err != nil {
		return nil, fmt.Errorf("ca func failed to get credentials: %v", err)
	}
	if creds.proxyConfig == nil {
		return a.clusterCA, nil
	}
	return creds.proxyConfig.ca, nil
}

func (a *Authenticator) proxy(req *http.Request) (*url.URL, error) {
	creds, err := a.getCreds()
	if err != nil {
		return nil, fmt.Errorf("proxy func failed to get credentials: %v", err)
	}
	if creds.proxyConfig == nil {
		return a.clusterProxy(req)
	}
	return nil, nil // no proxy when using exec proxy since that is delegated to the plugin
}

func (a *Authenticator) getProxyCertFailed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.proxyCertFailed
}

func (a *Authenticator) setProxyCertFailed() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.proxyCertFailed = true
}

func (a *Authenticator) getProxyCertUsed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.proxyCertUsed
}

func (a *Authenticator) setProxyCertUsed() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.proxyCertUsed = true
}

func (a *Authenticator) getCreds() (*credentials, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cachedCreds != nil && !a.credsExpired() {
		return a.cachedCreds, nil
	}

	if err := a.refreshCredsLocked(nil); err != nil {
		return nil, err
	}

	return a.cachedCreds, nil
}

// maybeRefreshCreds executes the plugin to force a rotation of the
// credentials, unless they were rotated already.
func (a *Authenticator) maybeRefreshCreds(creds *credentials, r *clientauthentication.Response) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Since we're not making a new pointer to a.cachedCreds in getCreds, no
	// need to do deep comparison.
	if creds != a.cachedCreds {
		// Credentials already rotated.
		return nil
	}

	return a.refreshCredsLocked(r)
}

// refreshCredsLocked executes the plugin and reads the credentials from
// stdout. It must be called while holding the Authenticator's mutex.
func (a *Authenticator) refreshCredsLocked(r *clientauthentication.Response) error {
	interactive, err := a.interactiveFunc()
	if err != nil {
		return fmt.Errorf("exec plugin cannot support interactive mode: %w", err)
	}

	cred := &clientauthentication.ExecCredential{
		Spec: clientauthentication.ExecCredentialSpec{
			Response:    r,
			Interactive: interactive,
		},
	}
	if a.provideClusterInfo {
		cred.Spec.Cluster = a.cluster
	}

	env := append(a.environ(), a.env...)
	data, err := runtime.Encode(codecs.LegacyCodec(a.group), cred)
	if err != nil {
		return fmt.Errorf("encode ExecCredentials: %v", err)
	}
	env = append(env, fmt.Sprintf("%s=%s", execInfoEnv, data))

	stdoutRead, stdoutWrite := io.Pipe()
	cmd := exec.Command(a.cmd, a.args...)
	cmd.Env = env
	cmd.Stderr = a.stderr
	cmd.Stdout = stdoutWrite
	if interactive {
		cmd.Stdin = a.stdin
	}

	startErr := cmd.Start()
	if startErr != nil {
		incrementCallsMetric(a.callsMetric, startErr) // only increment success metric on Wait
		return a.wrapCmdRunErrorLocked(startErr)
	}

	waitCh := make(chan error)
	go func() {
		waitCh <- cmd.Wait()
	}()

	type decodeData struct {
		status *clientauthentication.ExecCredentialStatus
		gvk    *schema.GroupVersionKind
		err    error
	}
	decodeCh := make(chan decodeData)
	go func() {
		defer func() {
			_ = stdoutRead.Close() // should always return nil per go doc
		}()

		out := &clientauthentication.ExecCredential{}
		frameReader := framer.NewFrameReader(stdoutRead)
		_, gvk, err := streaming.NewDecoder(frameReader, codecs.UniversalDecoder(a.group)).Decode(nil, out)
		decodeCh <- decodeData{status: out.Status, gvk: gvk, err: err}
	}()

	var (
		doneWaiting, doneDecoding bool
		waitErr                   error
		dd                        decodeData
	)
done:
	for {
		if doneWaiting && doneDecoding {
			break
		}

		select {
		case waitErr = <-waitCh:
			doneWaiting = true

			if waitErr != nil {
				break done // do not wait for decoding if the binary failed to run
			}

		case dd = <-decodeCh:
			doneDecoding = true

			if dd.status != nil && dd.status.ProxyConfig != nil {
				break done // this plugin needs to run as a proxy, do not wait for it to complete
			}
		}
	}

	if doneWaiting {
		incrementCallsMetric(a.callsMetric, waitErr)
		if waitErr != nil {
			return a.wrapCmdRunErrorLocked(waitErr)
		}
	} else {
		go func() {
			asyncWaitErr := <-waitCh
			incrementCallsMetric(a.callsMetric, asyncWaitErr)
			if asyncWaitErr != nil { // this plugin runs as a proxy so exit errors are informational
				klog.V(2).Infof("waiting process did not exit cleanly: %v", a.wrapCmdRunErrorLocked(asyncWaitErr)) // TODO close connections?
			}
		}()
	}

	if dd.err != nil {
		return fmt.Errorf("decoding stdout: %v", dd.err)
	}
	if dd.gvk.Group != a.group.Group || dd.gvk.Version != a.group.Version {
		return fmt.Errorf("exec plugin is configured to use API version %s, plugin returned version %s",
			a.group, schema.GroupVersion{Group: dd.gvk.Group, Version: dd.gvk.Version})
	}

	cred.Status = dd.status

	if cred.Status == nil {
		return fmt.Errorf("exec plugin didn't return a status field")
	}
	if cred.Status.Token == "" && cred.Status.ClientCertificateData == "" && cred.Status.ClientKeyData == "" {
		return fmt.Errorf("exec plugin didn't return a token or cert/key pair")
	}
	if (cred.Status.ClientCertificateData == "") != (cred.Status.ClientKeyData == "") {
		return fmt.Errorf("exec plugin returned only certificate or key, not both")
	}

	if cred.Status.ExpirationTimestamp != nil {
		a.exp = cred.Status.ExpirationTimestamp.Time
	} else {
		a.exp = time.Time{}
	}

	newCreds := &credentials{
		token: cred.Status.Token,
	}
	if cred.Status.ClientKeyData != "" && cred.Status.ClientCertificateData != "" {
		cert, err := tls.X509KeyPair([]byte(cred.Status.ClientCertificateData), []byte(cred.Status.ClientKeyData))
		if err != nil {
			return fmt.Errorf("failed parsing client key/certificate: %v", err)
		}

		// Leaf is initialized to be nil:
		//  https://golang.org/pkg/crypto/tls/#X509KeyPair
		// Leaf certificate is the first certificate:
		//  https://golang.org/pkg/crypto/tls/#Certificate
		// Populating leaf is useful for quickly accessing the underlying x509
		// certificate values.
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed parsing client leaf certificate: %v", err)
		}
		newCreds.cert = &cert
	}
	// TODO validate this data -> no expiration, must have client cert, no token?
	//  if proxy quits, make the creds expired, and close connections
	//  when proxyConfig is specified, re-entering this method would occur on 401 or if we expired the creds
	//  we could kill the proxy and then run again?
	//  also need to make sure proxy process dies when kubectl dies
	if p := cred.Status.ProxyConfig; p != nil {
		newCreds.proxyConfig = &proxyConfig{
			port: p.Port,
		}
		if len(p.CertificateAuthorityData) > 0 {
			newCreds.proxyConfig.ca = x509.NewCertPool()
			if ok := newCreds.proxyConfig.ca.AppendCertsFromPEM(p.CertificateAuthorityData); !ok {
				return errors.New("exec plugin returned invalid proxy CA data")
			}
		}
	}

	oldCreds := a.cachedCreds
	a.cachedCreds = newCreds
	// Only close all connections when TLS cert rotates. Token rotation doesn't
	// need the extra noise.
	if oldCreds != nil && !reflect.DeepEqual(oldCreds.cert, a.cachedCreds.cert) { // TODO close connections if CA changes?
		// Can be nil if the exec auth plugin only returned token auth.
		if oldCreds.cert != nil && oldCreds.cert.Leaf != nil {
			metrics.ClientCertRotationAge.Observe(time.Since(oldCreds.cert.Leaf.NotBefore))
		}
		a.connTracker.CloseAll()
	}

	expiry := time.Time{}
	if a.cachedCreds.cert != nil && a.cachedCreds.cert.Leaf != nil {
		expiry = a.cachedCreds.cert.Leaf.NotAfter
	}
	expirationMetrics.set(a, expiry)
	return nil
}

// wrapCmdRunErrorLocked pulls out the code to construct a helpful error message
// for when the exec plugin's binary fails to Run().
//
// It must be called while holding the Authenticator's mutex.
func (a *Authenticator) wrapCmdRunErrorLocked(err error) error {
	switch err.(type) {
	case *exec.Error: // Binary does not exist (see exec.Error).
		builder := strings.Builder{}
		fmt.Fprintf(&builder, "exec: executable %s not found", a.cmd)

		a.sometimes.Do(func() {
			fmt.Fprint(&builder, installHintVerboseHelp)
			if a.installHint != "" {
				fmt.Fprintf(&builder, "\n\n%s", a.installHint)
			}
		})

		return errors.New(builder.String())

	case *exec.ExitError: // Binary execution failed (see exec.Cmd.Run()).
		e := err.(*exec.ExitError)
		return fmt.Errorf(
			"exec: executable %s failed with exit code %d",
			a.cmd,
			e.ProcessState.ExitCode(),
		)

	default:
		return fmt.Errorf("exec: %v", err)
	}
}
