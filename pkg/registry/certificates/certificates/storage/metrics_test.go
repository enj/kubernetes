package storage

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/metrics"
	"k8s.io/kubernetes/pkg/apis/certificates"
	"k8s.io/utils/pointer"
)

func Test_countCSRDurationMetric(t *testing.T) {
	requested := csrDurationRequested
	honored := csrDurationHonored
	t.Cleanup(func() {
		csrDurationRequested = requested
		csrDurationHonored = honored
	})

	tests := []struct {
		name                       string
		setup                      func(*testing.T)
		success                    bool
		obj, old                   *certificates.CertificateSigningRequest
		options                    *metav1.UpdateOptions
		wantLabel                  string
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
			wantLabel:     "foo",
			wantRequested: true,
			wantHonored:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testReq := &testCounterVecMetric{}
			testHon := &testCounterVecMetric{}

			csrDurationRequested = testReq
			csrDurationHonored = testHon

			finishFunc, err := countCSRDurationMetric(nil, tt.obj, tt.old, tt.options)
			if err != nil {
				t.Fatal(err)
			}

			finishFunc(nil, tt.success)

			if got := testReq.label; tt.wantRequested && tt.wantLabel != got {
				t.Errorf("requested label: want %v, got %v", tt.wantLabel, got)
			}

			if got := testHon.label; tt.wantHonored && tt.wantLabel != got {
				t.Errorf("honored label: want %v, got %v", tt.wantLabel, got)
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
	metrics.Registerable
	metrics.CounterMetric

	label  string
	called bool
}

func (m *testCounterVecMetric) WithLabelValues(lv ...string) metrics.CounterMetric {
	if len(lv) != 1 {
		panic(lv)
	}

	if len(m.label) != 0 {
		panic("unexpected multiple WithLabelValues() calls")
	}

	label := lv[0]

	if len(label) == 0 {
		panic("invalid empty label")
	}

	m.label = label
	return m
}

func (m *testCounterVecMetric) Inc() {
	if m.called {
		panic("unexpected multiple Inc() calls")
	}

	m.called = true
}
