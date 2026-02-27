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
			`,
		},
		{
			name:   "failed attempt",
			status: "failed",
			expectedValue: `
				# HELP apiserver_impersonation_attempts_total [ALPHA] Total number of impersonation attempts split by status. Status is the impersonation mode on success or 'failed' on failure.
				# TYPE apiserver_impersonation_attempts_total counter
				apiserver_impersonation_attempts_total{status="failed"} 1
			`,
		},
		{
			name:   "success with legacy mode",
			status: "legacy",
			expectedValue: `
				# HELP apiserver_impersonation_attempts_total [ALPHA] Total number of impersonation attempts split by status. Status is the impersonation mode on success or 'failed' on failure.
				# TYPE apiserver_impersonation_attempts_total counter
				apiserver_impersonation_attempts_total{status="legacy"} 1
			`,
		},
	}

	metrics := []string{
		namespace + "_" + subsystem + "_attempts_total",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			impersonationAttemptsTotal.Reset()

			RecordImpersonationAttempt(tc.status, time.Millisecond)
			if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(tc.expectedValue), metrics...); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecordImpersonationAttemptDuration(t *testing.T) {
	RegisterMetrics()
	impersonationDurationSeconds.Reset()

	RecordImpersonationAttempt("user-info", 100*time.Millisecond)

	expectedValue := `
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
	`

	metrics := []string{
		namespace + "_" + subsystem + "_duration_seconds",
	}

	if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedValue), metrics...); err != nil {
		t.Fatal(err)
	}
}

func TestRecordImpersonationAuthorizationCall(t *testing.T) {
	RegisterMetrics()

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
			`,
		},
	}

	metrics := []string{
		namespace + "_" + subsystem + "_authorization_attempts_total",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			impersonationAuthorizationAttemptsTotal.Reset()

			RecordImpersonationAuthorizationCall(tc.mode, tc.decision, time.Millisecond)
			if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(tc.expectedValue), metrics...); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecordImpersonationAuthorizationCallMultiple(t *testing.T) {
	RegisterMetrics()
	ResetMetricsForTest()

	RecordImpersonationAuthorizationCall("user-info", "allowed", time.Millisecond)
	RecordImpersonationAuthorizationCall("user-info", "allowed", time.Millisecond)
	RecordImpersonationAuthorizationCall("user-info", "denied", time.Millisecond)
	RecordImpersonationAuthorizationCall("legacy", "denied", time.Millisecond)

	expectedValue := `
		# HELP apiserver_impersonation_authorization_attempts_total [ALPHA] Total number of authorization checks made by the impersonation handler split by mode and decision.
		# TYPE apiserver_impersonation_authorization_attempts_total counter
		apiserver_impersonation_authorization_attempts_total{decision="allowed",mode="user-info"} 2
		apiserver_impersonation_authorization_attempts_total{decision="denied",mode="legacy"} 1
		apiserver_impersonation_authorization_attempts_total{decision="denied",mode="user-info"} 1
	`

	metrics := []string{
		namespace + "_" + subsystem + "_authorization_attempts_total",
	}

	if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedValue), metrics...); err != nil {
		t.Fatal(err)
	}
}
