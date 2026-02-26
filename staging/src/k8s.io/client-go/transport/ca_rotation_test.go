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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	clientgofeaturegate "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	testingclock "k8s.io/utils/clock/testing"
	netutils "k8s.io/utils/net"
)

const (
	// Use the same rootCACert as transport_test.go
	testCACert1 = `-----BEGIN CERTIFICATE-----
MIIC4DCCAcqgAwIBAgIBATALBgkqhkiG9w0BAQswIzEhMB8GA1UEAwwYMTAuMTMu
MTI5LjEwNkAxNDIxMzU5MDU4MB4XDTE1MDExNTIxNTczN1oXDTE2MDExNTIxNTcz
OFowIzEhMB8GA1UEAwwYMTAuMTMuMTI5LjEwNkAxNDIxMzU5MDU4MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAunDRXGwsiYWGFDlWH6kjGun+PshDGeZX
xtx9lUnL8pIRWH3wX6f13PO9sktaOWW0T0mlo6k2bMlSLlSZgG9H6og0W6gLS3vq
s4VavZ6DbXIwemZG2vbRwsvR+t4G6Nbwelm6F8RFnA1Fwt428pavmNQ/wgYzo+T1
1eS+HiN4ACnSoDSx3QRWcgBkB1g6VReofVjx63i0J+w8Q/41L9GUuLqquFxu6ZnH
60vTB55lHgFiDLjA1FkEz2dGvGh/wtnFlRvjaPC54JH2K1mPYAUXTreoeJtLJKX0
ycoiyB24+zGCniUmgIsmQWRPaOPircexCp1BOeze82BT1LCZNTVaxQIDAQABoyMw
ITAOBgNVHQ8BAf8EBAMCAKQwDwYDVR0TAQH/BAUwAwEB/zALBgkqhkiG9w0BAQsD
ggEBADMxsUuAFlsYDpF4fRCzXXwrhbtj4oQwcHpbu+rnOPHCZupiafzZpDu+rw4x
YGPnCb594bRTQn4pAu3Ac18NbLD5pV3uioAkv8oPkgr8aUhXqiv7KdDiaWm6sbAL
EHiXVBBAFvQws10HMqMoKtO8f1XDNAUkWduakR/U6yMgvOPwS7xl0eUTqyRB6zGb
K55q2dejiFWaFqB/y78txzvz6UlOZKE44g2JAVoJVM6kGaxh33q8/FmrL4kuN3ut
W+MmJCVDvd4eEqPwbp7146ZWTqpIJ8lvA6wuChtqV8lhAPka2hD/LMqY8iXNmfXD
uml0obOEy+ON91k+SWTJ3ggmF/U=
-----END CERTIFICATE-----`

	// A different CA cert for testing rotation (modified version of certData from transport_test.go)
	testCACert2 = `-----BEGIN CERTIFICATE-----
MIIC6jCCAdSgAwIBAgIBCzALBgkqhkiG9w0BAQswIzEhMB8GA1UEAwwYMTAuMTMu
MTI5LjEwNkAxNDIxMzU5MDU4MB4XDTE1MDExNTIyMDEzMVoXDTE2MDExNTIyMDEz
MlowGzEZMBcGA1UEAxMQb3BlbnNoaWZ0LWNsaWVudDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAKtdhz0+uCLXw5cSYns9rU/XifFSpb/x24WDdrm72S/v
b9BPYsAStiP148buylr1SOuNi8sTAZmlVDDIpIVwMLff+o2rKYDicn9fjbrTxTOj
lI4pHJBH+JU3AJ0tbajupioh70jwFS0oYpwtneg2zcnE2Z4l6mhrj2okrc5Q1/X2
I2HChtIU4JYTisObtin10QKJX01CLfYXJLa8upWzKZ4/GOcHG+eAV3jXWoXidtjb
1Usw70amoTZ6mIVCkiu1QwCoa8+ycojGfZhvqMsAp1536ZcCul+Na+AbCv4zKS7F
kQQaImVrXdUiFansIoofGlw/JNuoKK6ssVpS5Ic3pgcCAwEAAaM1MDMwDgYDVR0P
AQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwCwYJ
KoZIhvcNAQELA4IBAQCKLREH7bXtXtZ+8vI6cjD7W3QikiArGqbl36bAhhWsJLp/
p/ndKz39iFNaiZ3GlwIURWOOKx3y3GA0x9m8FR+Llthf0EQ8sUjnwaknWs0Y6DQ3
jjPFZOpV3KPCFrdMJ3++E3MgwFC/Ih/N2ebFX9EcV9Vcc6oVWMdwT0fsrhu683rq
6GSR/3iVX1G/pmOiuaR0fNUaCyCfYrnI4zHBDgSfnlm3vIvN2lrsR/DQBakNL8DJ
HBgKxMGeUPoneBv+c8DMXIL0EhaFXRlBv9QW45/GiAIOuyFJ0i6hCtGZpJjq4OpQ
BRjCI+izPzFTjsxD4aORE+WOkyWFCGPWKfNejfw0
-----END CERTIFICATE-----`
)

// writeCAFile writes CA data to a temporary file
func writeCAFile(t testing.TB, caData []byte) string {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")

	err := os.WriteFile(caFile, caData, 0644)
	if err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(caFile); err != nil {
			t.Fatalf("unexpected error while removing file: %s - %v", caFile, err)
		}
	})
	return caFile
}

// createTestTransport creates a test transport with TLS config
func createTestTransport(t testing.TB, caData []byte) *http.Transport {
	CAs, err := rootCertPool(caData)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate")
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: CAs,
		},
	}
}

func TestCheckCAFileAndRotate(t *testing.T) {
	tests := []struct {
		name           string
		setupCA        []byte
		updateCA       []byte
		caFileOverride string
		expectRotation bool
	}{
		{
			name:           "no change",
			setupCA:        []byte(testCACert1),
			updateCA:       []byte(testCACert1), // Same CA
			expectRotation: false,
		},
		{
			name:           "CA changed",
			setupCA:        []byte(testCACert1),
			updateCA:       []byte(testCACert2), // Different CA
			expectRotation: true,
		},
		{
			name:           "CA changed to invalid",
			setupCA:        []byte(testCACert1),
			updateCA:       []byte("panda"), // invalid CA
			expectRotation: false,
		},
		{
			name:           "file error",
			setupCA:        []byte(testCACert1),
			caFileOverride: "/nonexistent/ca.crt", // Non-existent file
			expectRotation: false,
		},
		{
			name:           "empty file content",
			setupCA:        []byte(testCACert1),
			updateCA:       []byte{}, // Empty file
			expectRotation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caFile := writeCAFile(t, tt.setupCA)
			if len(tt.caFileOverride) > 0 {
				caFile = tt.caFileOverride
			}

			transport := createTestTransport(t, tt.setupCA)
			setupRoots := transport.TLSClientConfig.RootCAs.Clone()

			expectedRoots := setupRoots
			if tt.expectRotation {
				var err error
				expectedRoots, err = rootCertPool(tt.updateCA)
				if err != nil {
					t.Fatal(err)
				}
			}

			clock := testingclock.NewFakeClock(time.Now())
			holder := newAtomicTransportHolder(caFile, tt.setupCA, transport)
			holder.clock = clock
			holder.transportLastChecked = clock.Now()

			if tt.updateCA != nil {
				// Update the file with new CA content
				err := os.WriteFile(caFile, tt.updateCA, 0644)
				if err != nil {
					t.Errorf("Failed to update CA data with file address: %s", caFile)
				}
			}

			clock.Step(holder.caRefreshDuration)

			// Check CA file rotation
			newTransport := holder.getTransport(t.Context())
			newRoots := newTransport.TLSClientConfig.RootCAs

			if newRoots == nil || !expectedRoots.Equal(newRoots) {
				t.Error("new roots did not match expected roots")
			}

			transportRotated := newTransport != transport
			if tt.expectRotation != transportRotated {
				t.Error("transport rotation did not match")
			}

		})
	}
}

// TODO(review): use k8s.io/client-go/util/cert instead
// createTestCertificateAuthority creates a test CA certificate and key
func createTestCertificateAuthority(t testing.TB, commonName string) ([]byte, crypto.PrivateKey, []byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Add IP SANs for 127.0.0.1 and DNS names for localhost
		IPAddresses: []net.IP{netutils.ParseIPSloppy("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return certDER, privateKey, keyPEM, certPEM, nil
}

// TODO(review): use k8s.io/client-go/util/cert instead
// createTestClientCertificate creates a client certificate signed by the given CA
func createTestClientCertificate(t testing.TB, caCertPEM []byte, caKey crypto.PrivateKey, commonName string) ([]byte, []byte, error) {
	// Parse CA certificate
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Generate client private key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create client certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

// TestCARotationConnectionBehavior tests that CA rotation
func TestCARotationConnectionBehavior(t *testing.T) {
	t.Log("Testing CA Rotation Connection Behavior")

	// TODO(review): add tests for when this is disabled
	clientfeaturestesting.SetFeatureDuringTest(t, clientgofeaturegate.ClientsAllowCARotation, true)

	// Create initial CA and server certificates
	serverCert1, serverKey1, serverKeyPem1, serverCA1, err := createTestCertificateAuthority(t, "test-server-1")
	if err != nil {
		t.Fatalf("Failed to create initial server CA: %v", err)
	}

	clientCert1, clientKey1, err := createTestClientCertificate(t, serverCA1, serverKey1, "test-client-1")
	if err != nil {
		t.Fatalf("Failed to create initial client cert: %v", err)
	}

	// Start the first server
	combinedCaPool := x509.NewCertPool()
	combinedCaPool.AppendCertsFromPEM(serverCA1)
	server1 := newTestServer(t, serverCert1, serverKeyPem1, combinedCaPool)
	server1.StartTLS()
	defer server1.Close()

	// Set up the client
	clientCAFile := writeCAFile(t, serverCA1)
	config := &Config{
		TLS: TLSConfig{
			CAFile:   clientCAFile,
			CertData: clientCert1,
			KeyData:  clientKey1,
		},
	}

	transport, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}
	// Speed up the refresh duration for this test
	transport.(*atomicTransportHolder).caRefreshDuration = 500 * time.Millisecond

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Initial connection must succeed, establishing a baseline
	t.Log("Making initial request to server v1, expecting success...")
	resp, err := client.Get(server1.URL)
	if err != nil {
		t.Fatalf("Failed to call the server v1: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal("Failed to close the response.")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatal("Failed to call the server successfully.")
	}

	t.Log("Initial connection successful.")

	// Stop the old server and start a new one on the SAME address with the NEW certificate
	t.Log("Stopping server v1 and starting server v2 with a new certificate...")
	server1Addr := server1.Listener.Addr().String()
	server1.Close() // This releases the port

	serverCert2, _, serverKeyPem2, serverCA2, err := createTestCertificateAuthority(t, "test-server-2")
	if err != nil {
		t.Fatalf("Failed to create initial server CA: %v", err)
	}
	combinedCaPool.AppendCertsFromPEM(serverCA2)
	server2 := newTestServer(t, serverCert2, serverKeyPem2, combinedCaPool)
	l, err := net.Listen("tcp", server1Addr) // Re-claim the same address
	if err != nil {
		t.Fatalf("Failed to re-claim the same server address: %v", err)
	}
	server2.Listener = l
	server2.StartTLS()
	defer server2.Close()

	// Connection must now fail, as the client doesn't trust the new CA yet
	t.Log("Making request to server v2, expecting failure...")
	_, err = client.Get(server2.URL)
	if err == nil {
		t.Fatal("The request should fail.")
	}
	t.Log("Request failed as expected.")

	// Update the client's CA file on disk to trust the new CA
	t.Log("Updating client CA file on disk to trust ca-v2...")
	err = os.WriteFile(clientCAFile, serverCA2, 0644)
	if err != nil {
		t.Fatalf("Failed to update CA file: %v", err)
	}

	// Poll continuously until the client recovers and the connection succeeds
	t.Log("Polling server v2 until the client's transport reloads the new CA...")
	var lastPollErr error
	ctx, ctxCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxCancel()
	waitConditionFunc := func(ctx context.Context) (bool, error) {
		resp, err := client.Get(server2.URL)
		if err != nil {
			lastPollErr = err // Store the last error for logging
			t.Log("Client failed to connect before the root CAs are updated, will retry...")
			return false, nil // Error is expected, continue polling
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal("Failed to close the response.")
		}
		if resp.StatusCode == http.StatusOK {
			return true, nil // Success! Stop polling.
		}
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	pollErr := wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, waitConditionFunc)

	if pollErr != nil {
		t.Fatalf("Client failed to reconnect after CA rotation. Last error: %v. Test error: %v", lastPollErr, pollErr)
	}

	t.Log("Success! Client reconnected after CA was refreshed.")
}

// helper to create a simple, non-blocking test server with a given certificate.
func newTestServer(t *testing.T, serverCert, serverKey []byte, caPool *x509.CertPool) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := fmt.Fprint(w, "ok"); err != nil {
			t.Fatal("Failed to write to the response.")
		}
	}))
	// Configure server TLS
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert}),
		serverKey,
	)
	if err != nil {
		t.Fatalf("Failed to create server cert: %v", err)
	}

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}

	return server
}
