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

package rest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/util/cert"
	certutil "k8s.io/client-go/util/cert"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/kubelet/client"
	"k8s.io/kubernetes/pkg/registry/registrytest"
)

func TestPodLogValidates(t *testing.T) {
	config, server := registrytest.NewEtcdStorage(t, "")
	defer server.Terminate(t)
	s, destroyFunc, err := generic.NewRawStorage(config, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer destroyFunc()
	store := &genericregistry.Store{
		Storage: genericregistry.DryRunnableStorage{Storage: s},
	}
	logRest := &LogREST{Store: store, KubeletConn: nil}

	negativeOne := int64(-1)
	testCases := []*api.PodLogOptions{
		{SinceSeconds: &negativeOne},
		{TailLines: &negativeOne},
	}

	for _, tc := range testCases {
		_, err := logRest.Get(genericapirequest.NewDefaultContext(), "test", tc)
		if !errors.IsInvalid(err) {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
}

func TestPodLogTLS(t *testing.T) {
	config, server := registrytest.NewEtcdStorage(t, "")
	defer server.Terminate(t)

	newFunc := func() runtime.Object { return &api.Pod{} }
	s, destroyFunc, err := generic.NewRawStorage(config, newFunc)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if err := s.Create(context.TODO(), "key", &api.Pod{
		Spec: api.PodSpec{
			NodeName: "a node",
			Containers: []api.Container{
				{
					Name: "foo",
				},
			},
		},
	}, nil, 0); err != nil {
		t.Fatal(err)
	}

	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "test-ca"}, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	// caPrivateKeyBytes, err := keyutil.MarshalPrivateKeyToPEM(caPrivateKey)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	servingPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var c atomic.Int64

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(`some pod logs here`))
	}))
	ts.TLS = &tls.Config{
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
					c.Add(1)
					t.Log("CALLED", c.Load())
					servingCert, err := newSignedCert(
						&cert.Config{
							CommonName: "hello",
							AltNames: certutil.AltNames{
								IPs: []net.IP{
									net.ParseIP("127.0.0.1"),
									net.ParseIP("::1"),
								},
							},
							Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
						},
						servingPrivateKey, caCert, caPrivateKey,
					)
					if err != nil {
						return nil, err
					}
					return &tls.Certificate{
						Certificate: [][]byte{servingCert.Raw},
						PrivateKey:  servingPrivateKey,
						Leaf:        servingCert,
					}, nil
				},
			}, nil
		},
	}
	ts.StartTLS()
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	caBundle := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	defer destroyFunc()
	store := &genericregistry.Store{
		NewFunc: newFunc,
		KeyFunc: func(ctx context.Context, name string) (string, error) {
			return "key", nil
		},
		Storage: genericregistry.DryRunnableStorage{Storage: s},
	}

	k, err := client.NewNodeConnectionInfoGetter(
		client.NodeGetterFunc(func(ctx context.Context, name string, options metav1.GetOptions) (*corev1.Node, error) {
			return &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: host,
						},
					},
					DaemonEndpoints: corev1.NodeDaemonEndpoints{
						KubeletEndpoint: corev1.DaemonEndpoint{
							Port: int32(port),
						},
					},
				},
			}, nil
		}),
		client.KubeletClientConfig{
			PreferredAddressTypes: []string{string(corev1.NodeInternalIP)},
			TLS: restclient.TLSClientConfig{
				ServerName: "",
				CAData:     caBundle,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	logRest := &LogREST{Store: store, KubeletConn: k}

	loc, err := logRest.Get(context.TODO(), "TODO", &api.PodLogOptions{})
	if err != nil {
		t.Fatal(err)
	}

	out, _, _, err := loc.(rest.ResourceStreamer).InputStream(context.TODO(), "", "")
	if err != nil {
		t.Fatal(err)
	}

	if false {
		data, err := io.ReadAll(out)
		if err != nil {
			t.Fatal(err)
		}
		_ = out.Close()

		t.Error(string(data))
	}

	time.Sleep(30 * time.Second)

	out2, _, _, err := loc.(rest.ResourceStreamer).InputStream(context.TODO(), "", "")
	if err != nil {
		t.Fatal(err)
	}

	data2, err := io.ReadAll(out2)
	if err != nil {
		t.Fatal(err)
	}
	_ = out2.Close()

	t.Error(string(data2))
}

func newSignedCert(cfg *certutil.Config, key crypto.Signer, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, error) {
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	if len(cfg.CommonName) == 0 {
		return nil, fmt.Errorf("must specify a CommonName")
	}
	if len(cfg.Usages) == 0 {
		return nil, fmt.Errorf("must specify at least one ExtKeyUsage")
	}

	certTmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		NotBefore:    caCert.NotBefore,
		NotAfter:     time.Now().Add(5 * time.Second).UTC(),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  cfg.Usages,
	}
	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &certTmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}
