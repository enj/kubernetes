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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/cert"
	"k8s.io/kubernetes/test/utils"
)

func TestMakeTransportInvalid(t *testing.T) {
	config := &KubeletClientConfig{
		// Invalid certificate and key path
		TLSClientConfig: KubeletTLSConfig{
			CertFile: "../../client/testdata/mycertinvalid.cer",
			KeyFile:  "../../client/testdata/mycertinvalid.key",
			CAFile:   "../../client/testdata/myCA.cer",
		},
	}

	rt, err := MakeTransport(config)
	if err == nil {
		t.Errorf("Expected an error")
	}
	if rt != nil {
		t.Error("rt should be nil as we provided invalid cert file")
	}
}

func TestMakeTransportValid(t *testing.T) {
	config := &KubeletClientConfig{
		Port: 1234,
		TLSClientConfig: KubeletTLSConfig{
			CertFile: "../../client/testdata/mycertvalid.cer",
			// TLS Configuration
			KeyFile: "../../client/testdata/mycertvalid.key",
			// TLS Configuration
			CAFile: "../../client/testdata/myCA.cer",
		},
	}

	rt, err := MakeTransport(config)
	if err != nil {
		t.Errorf("Not expecting an error %#v", err)
	}
	if rt == nil {
		t.Error("rt should not be nil")
	}
}

func TestMakeInsecureTransport(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	testURL, err := url.Parse(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, err := net.SplitHostPort(testURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		t.Fatal(err)
	}

	config := &KubeletClientConfig{
		Port: uint(port),
		TLSClientConfig: KubeletTLSConfig{
			CertFile: "../../client/testdata/mycertvalid.cer",
			// TLS Configuration
			KeyFile: "../../client/testdata/mycertvalid.key",
			// TLS Configuration
			CAFile: "../../client/testdata/myCA.cer",
		},
	}

	rt, err := MakeInsecureTransport(config)
	if err != nil {
		t.Errorf("Not expecting an error #%v", err)
	}
	if rt == nil {
		t.Error("rt should not be nil")
	}

	req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		dump, err := httputil.DumpResponse(response, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal(string(dump))
	}
}

func TestValidateNodeName(t *testing.T) {
	const nodeName = "my-node-1"
	kubeletServer := newKubeletServer(t, nodeName)

	nodeGetter := NodeGetterFunc(func(ctx context.Context, name string, options metav1.GetOptions) (*corev1.Node, error) {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{
						Type: corev1.NodeInternalIP,
					},
				},
			},
		}, nil
	})

	kubeletClientConfig := KubeletClientConfig{
		TLSClientConfig: KubeletTLSConfig{
			CAFile:           kubeletServer.caFilePath,
			ValidateNodeName: false,
		},
		PreferredAddressTypes: []string{
			string(corev1.NodeInternalIP),
		},
	}
	nodeConnectionInfoGetter, err := NewNodeConnectionInfoGetter(nodeGetter, kubeletClientConfig)
	if err != nil {
		t.Fatal(err)
	}

	kubeletClientConfigWithValidateNodeName := kubeletClientConfig
	kubeletClientConfigWithValidateNodeName.TLSClientConfig.ValidateNodeName = true
	nodeConnectionInfoGetterWithValidateNodeName, err := NewNodeConnectionInfoGetter(nodeGetter, kubeletClientConfigWithValidateNodeName)
	if err != nil {
		t.Fatal(err)
	}

	// TODO test with multiple nodes and with connection re-use

	testCases := []struct {
		name                 string
		nodeName             types.NodeName
		connectionInfoGetter ConnectionInfoGetter
		expectErr            string
	}{
		{
			name:                 "valid cert",
			nodeName:             nodeName,
			connectionInfoGetter: nodeConnectionInfoGetterWithValidateNodeName,
		},
		{
			name:                 "invalid cert without validation",
			nodeName:             "my-node-2",
			connectionInfoGetter: nodeConnectionInfoGetter,
		},
		{
			name:                 "invalid cert with validation",
			nodeName:             "my-node-2",
			connectionInfoGetter: nodeConnectionInfoGetterWithValidateNodeName,
			expectErr:            `invalid node name; expected "system:node:my-node-2", got "system:node:my-node-1"`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nodeInfo, err := tc.connectionInfoGetter.GetConnectionInfo(t.Context(), tc.nodeName)
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequest(http.MethodGet, kubeletServer.server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := nodeInfo.Transport.RoundTrip(req)
			if err != nil && tc.expectErr == "" {
				t.Fatalf("Roundtrip failed: %s", err)
			}
			if err != nil && tc.expectErr != err.Error() {
				t.Fatalf("Expected error [%s], got: %s", tc.expectErr, err)
			}

			if err == nil && tc.expectErr != "" {
				t.Fatalf("Expected error [%s] but got success", err)
			}

			if err == nil && response.StatusCode != http.StatusOK {
				dump, err := httputil.DumpResponse(response, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatal(string(dump))
			}
		})
	}
}

type fakeKubeletServer struct {
	server     *httptest.Server
	caFilePath string
}

func newKubeletServer(tb testing.TB, nodeName string) *fakeKubeletServer {
	ca, err := createCA()
	if err != nil {
		tb.Fatal(err)
	}
	servingCert := createServingCert(tb, ca.cert, ca.key, nodeName)

	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	testServer.EnableHTTP2 = true // TODO test both with http1 and http2

	testServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{servingCert},
	}

	testServer.StartTLS()
	tb.Cleanup(testServer.Close)

	caPath := filepath.Join(tb.TempDir(), "test.ca")
	if err = os.WriteFile(caPath, ca.certPEM, 0o644); err != nil {
		tb.Fatal(err)
	}

	return &fakeKubeletServer{
		server:     testServer,
		caFilePath: caPath,
	}
}

type certificate struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
	keyPEM  []byte
}

func createCA() (*certificate, error) {
	now := time.Now()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key for CA: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number for CA: %w", err)
	}
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "kubernetes",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0), // 1 year
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})

	return &certificate{
		certPEM: caPEM.Bytes(),
		cert:    ca,
		key:     privateKey,
		keyPEM:  keyPEM.Bytes(),
	}, nil
}

func createServingCert(tb testing.TB, ca *x509.Certificate, caPrivKey crypto.Signer, nodeName string) tls.Certificate {
	tb.Helper()

	key, err := utils.NewPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}

	signedCert, err := utils.NewSignedCert(
		&cert.Config{
			CommonName: "system:node:" + nodeName,
			Organization: []string{
				"system:nodes",
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames: cert.AltNames{
				IPs: []net.IP{net.ParseIP("127.0.0.1")},
			},
		},
		key, ca, caPrivKey,
	)
	if err != nil {
		tb.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{signedCert.Raw},
		PrivateKey:  key,
	}
}
