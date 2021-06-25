package storage

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/metrics"
	"k8s.io/kubernetes/pkg/apis/certificates"
	"k8s.io/utils/pointer"
)

func Test_countCSRDurationMetric(t *testing.T) {
	tests := []struct {
		name                       string
		setup                      func(*testing.T)
		success                    bool
		obj, old                   *certificates.CertificateSigningRequest
		options                    *metav1.UpdateOptions
		wantSigner                 string
		wantRequested, wantHonored bool
	}{
		{
			name:    "cert parse failure",
			setup:   nil,
			success: true,
			obj: &certificates.CertificateSigningRequest{
				Status: certificates.CertificateSigningRequestStatus{
					Certificate: []byte("junk"),
				},
			},
			old: &certificates.CertificateSigningRequest{
				Spec: certificates.CertificateSigningRequestSpec{
					SignerName:        "fancy",
					ExpirationSeconds: pointer.Int32(77),
				},
			},
			options:       &metav1.UpdateOptions{},
			wantSigner:    "foo",
			wantRequested: true,
			wantHonored:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testReq := &testCounterVecMetric{}
			testHon := &testCounterVecMetric{}

			finishFunc, err := countCSRDurationMetric(testReq, testHon)(nil, tt.obj, tt.old, tt.options)
			if err != nil {
				t.Fatal(err)
			}

			finishFunc(nil, tt.success)

			if got := testReq.signer; tt.wantRequested && tt.wantSigner != got {
				t.Errorf("requested signer: want %v, got %v", tt.wantSigner, got)
			}

			if got := testHon.signer; tt.wantHonored && tt.wantSigner != got {
				t.Errorf("honored signer: want %v, got %v", tt.wantSigner, got)
			}

			if got := testReq.called; tt.wantRequested != got {
				t.Errorf("requested inc: want %v, got %v", tt.wantRequested, got)
			}

			if got := testHon.called; tt.wantHonored != got {
				t.Errorf("honored inc: want %v, got %v", tt.wantHonored, got)
			}
		})
	}
}

type testCounterVecMetric struct {
	metrics.CounterMetric

	signer string
	called bool
}

func (m *testCounterVecMetric) WithLabelValues(lv ...string) metrics.CounterMetric {
	if len(lv) != 1 {
		panic(lv)
	}

	if len(m.signer) != 0 {
		panic("unexpected multiple WithLabelValues() calls")
	}

	signer := lv[0]

	if len(signer) == 0 {
		panic("invalid empty signer")
	}

	m.signer = signer
	return m
}

func (m *testCounterVecMetric) Inc() {
	if m.called {
		panic("unexpected multiple Inc() calls")
	}

	m.called = true
}
