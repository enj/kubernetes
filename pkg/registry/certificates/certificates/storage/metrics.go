/*
Copyright 2021 The Kubernetes Authors.

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

package storage

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/features"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/util/dryrun"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/kubernetes/pkg/apis/certificates"
)

const (
	namespace = "apiserver"
	subsystem = "certificates_registry"
)

var (
	// csrDurationRequested counts and categorizes how many certificates were issued when the client requested a duration.
	csrDurationRequested = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      namespace,
			Subsystem:      subsystem,
			Name:           "csr_duration_requested",
			Help:           "Total number of issued CSRs with a requested duration, sliced by signer",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"signerName"},
	)

	// csrDurationHonored counts and categorizes how many certificates were issued when the client requested a duration and the signer honored it.
	csrDurationHonored = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      namespace,
			Subsystem:      subsystem,
			Name:           "csr_duration_honored",
			Help:           "Total number of issued CSRs with a requested duration that was honored, sliced by signer",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"signerName"},
	)
)

func init() {
	registerMetricsOnce.Do(func() {
		legacyregistry.MustRegister(csrDurationRequested)
		legacyregistry.MustRegister(csrDurationHonored)
	})
}

var registerMetricsOnce sync.Once

func TestCollectMetrics(ch chan<- prometheus.Metric) {
	csrDurationRequested.Collect(ch)
	csrDurationHonored.Collect(ch)
}

type counterVecMetric interface {
	WithLabelValues(...string) metrics.CounterMetric
}

func countCSRDurationMetric(requested, honored counterVecMetric) genericregistry.BeginUpdateFunc {
	return func(ctx context.Context, obj runtime.Object, old runtime.Object, options *metav1.UpdateOptions) (genericregistry.FinishFunc, error) {
		return func(ctx context.Context, success bool) {
			if !success {
				return
			}

			if dryrun.IsDryRun(options.DryRun) {
				return
			}

			if !utilfeature.DefaultFeatureGate.Enabled(features.CSRDuration) {
				return
			}

			newCSR := obj.(*certificates.CertificateSigningRequest)
			oldCSR := old.(*certificates.CertificateSigningRequest)

			if len(oldCSR.Status.Certificate) > 0 {
				return
			}

			if len(newCSR.Status.Certificate) == 0 {
				return
			}

			if oldCSR.Spec.ExpirationSeconds == nil {
				return
			}

			// TODO add comments
			// TODO add unit tests

			signer := compressSignerName(oldCSR.Spec.SignerName)

			requested.WithLabelValues(signer).Inc()

			certs, err := cert.ParseCertsPEM(newCSR.Status.Certificate)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("metrics recording failed to parse certificate for CSR %s: %w", newCSR.Name, err))
				return
			}

			certificate := certs[0]

			wantDuration := csr.ExpirationSecondsToDuration(*oldCSR.Spec.ExpirationSeconds)

			actualDuration := certificate.NotAfter.Sub(certificate.NotBefore)

			if isDurationHonored(wantDuration, actualDuration) {
				honored.WithLabelValues(signer).Inc()
			}
		}, nil
	}
}

func isDurationHonored(want time.Duration, got time.Duration) bool {
	delta := want - got
	if delta < 0 {
		delta = -delta
	}

	// short-lived cert backdating + 5% of want
	// TODO should we have an upper limit on the 5%?
	maxDelta := 5*time.Minute + (want / 20)

	return delta < maxDelta
}

func compressSignerName(name string) string {
	if strings.HasPrefix(name, "kubernetes.io/") {
		return name
	}

	return "other"
}
