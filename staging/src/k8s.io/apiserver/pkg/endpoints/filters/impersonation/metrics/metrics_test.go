/*
Copyright The Kubernetes Authors.

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

package metrics

import (
	"strings"
	"testing"
	"time"

	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"
)

func TestRecordImpersonationAttempt(t *testing.T) {
	RegisterMetrics()

	attemptMetrics := []string{
		namespace + "_" + subsystem + "_attempts_total",
		namespace + "_" + subsystem + "_duration_seconds",
	}

	testCases := []struct {
		name          string
		status        string
		expectedValue string
	}{
		{
			name:   "success with user-info mode",
			status: "user-info",
			expectedValue: `
				# HELP apiserver_impersonation_attempts_total [ALPHA] Total number of impersonation attempts split by status. Status is the impersonation mode on success or 'failed' on failure.
				# TYPE apiserver_impersonation_attempts_total counter
				apiserver_impersonation_attempts_total{status="user-info"} 1
				# HELP apiserver_impersonation_duration_seconds [ALPHA] Latency of impersonation attempts in seconds split by status. Status is the impersonation mode on success or 'failed' on failure.
				# TYPE apiserver_impersonation_duration_seconds histogram
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.005"} 0
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.01"} 0
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.025"} 0
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.05"} 0
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.1"} 1
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.25"} 1
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="1"} 1
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="2.5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="10"} 1
				apiserver_impersonation_duration_seconds_bucket{status="user-info",le="+Inf"} 1
				apiserver_impersonation_duration_seconds_sum{status="user-info"} 0.1
				apiserver_impersonation_duration_seconds_count{status="user-info"} 1
			`,
		},
		{
			name:   "failed attempt",
			status: "failed",
			expectedValue: `
				# HELP apiserver_impersonation_attempts_total [ALPHA] Total number of impersonation attempts split by status. Status is the impersonation mode on success or 'failed' on failure.
				# TYPE apiserver_impersonation_attempts_total counter
				apiserver_impersonation_attempts_total{status="failed"} 1
				# HELP apiserver_impersonation_duration_seconds [ALPHA] Latency of impersonation attempts in seconds split by status. Status is the impersonation mode on success or 'failed' on failure.
				# TYPE apiserver_impersonation_duration_seconds histogram
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.005"} 0
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.01"} 0
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.025"} 0
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.05"} 0
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.1"} 1
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.25"} 1
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="1"} 1
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="2.5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="10"} 1
				apiserver_impersonation_duration_seconds_bucket{status="failed",le="+Inf"} 1
				apiserver_impersonation_duration_seconds_sum{status="failed"} 0.1
				apiserver_impersonation_duration_seconds_count{status="failed"} 1
			`,
		},
		{
			name:   "success with legacy mode",
			status: "legacy",
			expectedValue: `
				# HELP apiserver_impersonation_attempts_total [ALPHA] Total number of impersonation attempts split by status. Status is the impersonation mode on success or 'failed' on failure.
				# TYPE apiserver_impersonation_attempts_total counter
				apiserver_impersonation_attempts_total{status="legacy"} 1
				# HELP apiserver_impersonation_duration_seconds [ALPHA] Latency of impersonation attempts in seconds split by status. Status is the impersonation mode on success or 'failed' on failure.
				# TYPE apiserver_impersonation_duration_seconds histogram
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="0.005"} 0
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="0.01"} 0
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="0.025"} 0
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="0.05"} 0
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="0.1"} 1
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="0.25"} 1
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="0.5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="1"} 1
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="2.5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="5"} 1
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="10"} 1
				apiserver_impersonation_duration_seconds_bucket{status="legacy",le="+Inf"} 1
				apiserver_impersonation_duration_seconds_sum{status="legacy"} 0.1
				apiserver_impersonation_duration_seconds_count{status="legacy"} 1
			`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetMetricsForTest()

			RecordImpersonationAttempt(tc.status, 100*time.Millisecond)

			if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(tc.expectedValue), attemptMetrics...); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecordImpersonationAuthorizationCall(t *testing.T) {
	RegisterMetrics()

	authorizationMetrics := []string{
		namespace + "_" + subsystem + "_authorization_attempts_total",
		namespace + "_" + subsystem + "_authorization_duration_seconds",
	}

	testCases := []struct {
		name          string
		mode          string
		decision      string
		expectedValue string
	}{
		{
			name:     "user-info allowed",
			mode:     "user-info",
			decision: "allowed",
			expectedValue: `
				# HELP apiserver_impersonation_authorization_attempts_total [ALPHA] Total number of authorization checks made by the impersonation handler split by mode and decision.
				# TYPE apiserver_impersonation_authorization_attempts_total counter
				apiserver_impersonation_authorization_attempts_total{decision="allowed",mode="user-info"} 1
				# HELP apiserver_impersonation_authorization_duration_seconds [ALPHA] Latency of authorization checks made by the impersonation handler in seconds split by mode and decision.
				# TYPE apiserver_impersonation_authorization_duration_seconds histogram
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.005"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.01"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.025"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.05"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.1"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.25"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="1"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="2.5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="10"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="+Inf"} 1
				apiserver_impersonation_authorization_duration_seconds_sum{decision="allowed",mode="user-info"} 0.1
				apiserver_impersonation_authorization_duration_seconds_count{decision="allowed",mode="user-info"} 1
			`,
		},
		{
			name:     "arbitrary-node denied",
			mode:     "arbitrary-node",
			decision: "denied",
			expectedValue: `
				# HELP apiserver_impersonation_authorization_attempts_total [ALPHA] Total number of authorization checks made by the impersonation handler split by mode and decision.
				# TYPE apiserver_impersonation_authorization_attempts_total counter
				apiserver_impersonation_authorization_attempts_total{decision="denied",mode="arbitrary-node"} 1
				# HELP apiserver_impersonation_authorization_duration_seconds [ALPHA] Latency of authorization checks made by the impersonation handler in seconds split by mode and decision.
				# TYPE apiserver_impersonation_authorization_duration_seconds histogram
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="0.005"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="0.01"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="0.025"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="0.05"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="0.1"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="0.25"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="0.5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="1"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="2.5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="10"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="arbitrary-node",le="+Inf"} 1
				apiserver_impersonation_authorization_duration_seconds_sum{decision="denied",mode="arbitrary-node"} 0.1
				apiserver_impersonation_authorization_duration_seconds_count{decision="denied",mode="arbitrary-node"} 1
			`,
		},
		{
			name:     "legacy allowed",
			mode:     "legacy",
			decision: "allowed",
			expectedValue: `
				# HELP apiserver_impersonation_authorization_attempts_total [ALPHA] Total number of authorization checks made by the impersonation handler split by mode and decision.
				# TYPE apiserver_impersonation_authorization_attempts_total counter
				apiserver_impersonation_authorization_attempts_total{decision="allowed",mode="legacy"} 1
				# HELP apiserver_impersonation_authorization_duration_seconds [ALPHA] Latency of authorization checks made by the impersonation handler in seconds split by mode and decision.
				# TYPE apiserver_impersonation_authorization_duration_seconds histogram
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="0.005"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="0.01"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="0.025"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="0.05"} 0
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="0.1"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="0.25"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="0.5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="1"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="2.5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="5"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="10"} 1
				apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="legacy",le="+Inf"} 1
				apiserver_impersonation_authorization_duration_seconds_sum{decision="allowed",mode="legacy"} 0.1
				apiserver_impersonation_authorization_duration_seconds_count{decision="allowed",mode="legacy"} 1
			`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetMetricsForTest()

			RecordImpersonationAuthorizationCall(tc.mode, tc.decision, 100*time.Millisecond)

			if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(tc.expectedValue), authorizationMetrics...); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecordImpersonationMetricsMultiple(t *testing.T) {
	RegisterMetrics()
	resetMetricsForTest()

	RecordImpersonationAttempt("user-info", 100*time.Millisecond)
	RecordImpersonationAttempt("failed", 50*time.Millisecond)
	RecordImpersonationAttempt("failed", 50*time.Millisecond)
	RecordImpersonationAuthorizationCall("user-info", "allowed", 100*time.Millisecond)
	RecordImpersonationAuthorizationCall("user-info", "allowed", 100*time.Millisecond)
	RecordImpersonationAuthorizationCall("user-info", "denied", 50*time.Millisecond)
	RecordImpersonationAuthorizationCall("legacy", "denied", 50*time.Millisecond)

	expectedValue := `
		# HELP apiserver_impersonation_attempts_total [ALPHA] Total number of impersonation attempts split by status. Status is the impersonation mode on success or 'failed' on failure.
		# TYPE apiserver_impersonation_attempts_total counter
		apiserver_impersonation_attempts_total{status="failed"} 2
		apiserver_impersonation_attempts_total{status="user-info"} 1
		# HELP apiserver_impersonation_authorization_attempts_total [ALPHA] Total number of authorization checks made by the impersonation handler split by mode and decision.
		# TYPE apiserver_impersonation_authorization_attempts_total counter
		apiserver_impersonation_authorization_attempts_total{decision="allowed",mode="user-info"} 2
		apiserver_impersonation_authorization_attempts_total{decision="denied",mode="legacy"} 1
		apiserver_impersonation_authorization_attempts_total{decision="denied",mode="user-info"} 1
		# HELP apiserver_impersonation_authorization_duration_seconds [ALPHA] Latency of authorization checks made by the impersonation handler in seconds split by mode and decision.
		# TYPE apiserver_impersonation_authorization_duration_seconds histogram
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.005"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.01"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.025"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.05"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.1"} 2
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.25"} 2
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="0.5"} 2
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="1"} 2
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="2.5"} 2
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="5"} 2
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="10"} 2
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="allowed",mode="user-info",le="+Inf"} 2
		apiserver_impersonation_authorization_duration_seconds_sum{decision="allowed",mode="user-info"} 0.2
		apiserver_impersonation_authorization_duration_seconds_count{decision="allowed",mode="user-info"} 2
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="0.005"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="0.01"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="0.025"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="0.05"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="0.1"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="0.25"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="0.5"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="1"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="2.5"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="5"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="10"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="legacy",le="+Inf"} 1
		apiserver_impersonation_authorization_duration_seconds_sum{decision="denied",mode="legacy"} 0.05
		apiserver_impersonation_authorization_duration_seconds_count{decision="denied",mode="legacy"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="0.005"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="0.01"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="0.025"} 0
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="0.05"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="0.1"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="0.25"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="0.5"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="1"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="2.5"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="5"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="10"} 1
		apiserver_impersonation_authorization_duration_seconds_bucket{decision="denied",mode="user-info",le="+Inf"} 1
		apiserver_impersonation_authorization_duration_seconds_sum{decision="denied",mode="user-info"} 0.05
		apiserver_impersonation_authorization_duration_seconds_count{decision="denied",mode="user-info"} 1
		# HELP apiserver_impersonation_duration_seconds [ALPHA] Latency of impersonation attempts in seconds split by status. Status is the impersonation mode on success or 'failed' on failure.
		# TYPE apiserver_impersonation_duration_seconds histogram
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.005"} 0
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.01"} 0
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.025"} 0
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.05"} 2
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.1"} 2
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.25"} 2
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="0.5"} 2
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="1"} 2
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="2.5"} 2
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="5"} 2
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="10"} 2
		apiserver_impersonation_duration_seconds_bucket{status="failed",le="+Inf"} 2
		apiserver_impersonation_duration_seconds_sum{status="failed"} 0.1
		apiserver_impersonation_duration_seconds_count{status="failed"} 2
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.005"} 0
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.01"} 0
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.025"} 0
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.05"} 0
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.1"} 1
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.25"} 1
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="0.5"} 1
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="1"} 1
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="2.5"} 1
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="5"} 1
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="10"} 1
		apiserver_impersonation_duration_seconds_bucket{status="user-info",le="+Inf"} 1
		apiserver_impersonation_duration_seconds_sum{status="user-info"} 0.1
		apiserver_impersonation_duration_seconds_count{status="user-info"} 1
	`

	allMetrics := []string{
		namespace + "_" + subsystem + "_attempts_total",
		namespace + "_" + subsystem + "_authorization_attempts_total",
		namespace + "_" + subsystem + "_authorization_duration_seconds",
		namespace + "_" + subsystem + "_duration_seconds",
	}

	if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedValue), allMetrics...); err != nil {
		t.Fatal(err)
	}
}

func resetMetricsForTest() {
	impersonationAttemptsTotal.Reset()
	impersonationDurationSeconds.Reset()
	impersonationAuthorizationAttemptsTotal.Reset()
	impersonationAuthorizationDurationSeconds.Reset()
}
