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
	"sync"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

const (
	namespace = "apiserver"
	subsystem = "certificates_registry"
)

var (
	// csrDurationRequested counts and categorizes how many certificates were issued when the client requested a duration.
	csrDurationRequested counterVecMetric = metrics.NewCounterVec(
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
	csrDurationHonored counterVecMetric = metrics.NewCounterVec(
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

type counterVecMetric interface {
	metrics.Registerable
	WithLabelValues(...string) metrics.CounterMetric
}
