/*
Copyright 2022 The Kubernetes Authors.

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

package controller

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/util/workqueue"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"
)

func TestController(t *testing.T) {
	defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.KMSv1, true)()

	tests := []struct {
		name                     string
		ecFilePath               string
		apiServerID              string
		validateECFileHash       bool
		validateTransformerClose bool
		validateSuccessMetric    bool
		validateFailureMetric    bool
		mockLoadEncryptionConfig func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error)
	}{
		{
			name:                     "when invalid config is provided previous config shouldn't be changed",
			ecFilePath:               "testdata/empty_config.yaml",
			apiServerID:              "test-apiserver",
			validateECFileHash:       true,
			validateTransformerClose: true,
			validateFailureMetric:    true,
			mockLoadEncryptionConfig: func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error) {
				return &encryptionconfig.EncryptionConfiguration{
					// hash of initial "testdata/ec_config.yaml" config file before reloading
					EncryptionFileContentHash: "6bc9f4aa2e5587afbb96074e1809550cbc4de3cc3a35717dac8ff2800a147fd3",
				}, fmt.Errorf("empty config file")
			},
		},
		{
			name:                  "when new valid config is provided it should be updated",
			ecFilePath:            "testdata/another_ec_config.yaml",
			apiServerID:           "test-apiserver",
			validateECFileHash:    true,
			validateSuccessMetric: true,
			mockLoadEncryptionConfig: func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error) {
				return &encryptionconfig.EncryptionConfiguration{
					HealthChecks: []healthz.HealthChecker{
						&mockHealthChecker{
							pluginName: "valid-plugin",
							err:        nil,
						},
					},
					// hash of "testdata/another_ec_config.yaml" config file
					EncryptionFileContentHash: "8851cada892961c7465a85c610ea9fbddb73b8d425b8c496a05c068679bdd798",
				}, nil
			},
		},
		{
			name:                     "when same valid config is provided previous config shouldn't be changed",
			ecFilePath:               "testdata/ec_config.yaml",
			apiServerID:              "test-apiserver",
			validateECFileHash:       true,
			validateTransformerClose: true,
			mockLoadEncryptionConfig: func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error) {
				return &encryptionconfig.EncryptionConfiguration{
					HealthChecks: []healthz.HealthChecker{
						&mockHealthChecker{
							pluginName: "valid-plugin",
							err:        nil,
						},
					},
					// hash of initial "testdata/ec_config.yaml" config file before reloading
					EncryptionFileContentHash: "6bc9f4aa2e5587afbb96074e1809550cbc4de3cc3a35717dac8ff2800a147fd3",
				}, nil
			},
		},
		{
			name:                     "when transformer's health check fails previous config shouldn't be changed",
			ecFilePath:               "testdata/another_ec_config.yaml",
			apiServerID:              "test-apiserver",
			validateECFileHash:       true,
			validateTransformerClose: true,
			mockLoadEncryptionConfig: func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error) {
				return &encryptionconfig.EncryptionConfiguration{
					HealthChecks: []healthz.HealthChecker{
						&mockHealthChecker{
							pluginName: "invalid-plugin",
							err:        fmt.Errorf("mockingly failing"),
						},
					},
					KMSCloseGracePeriod: time.Second,
					// hash of initial "testdata/ec_config.yaml" config file before reloading
					EncryptionFileContentHash: "6bc9f4aa2e5587afbb96074e1809550cbc4de3cc3a35717dac8ff2800a147fd3",
				}, nil
			},
		},
		{
			name:                     "when multiple health checks are present previous config shouldn't be changed",
			ecFilePath:               "testdata/another_ec_config.yaml",
			apiServerID:              "test-apiserver",
			validateECFileHash:       true,
			validateTransformerClose: true,
			mockLoadEncryptionConfig: func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error) {
				return &encryptionconfig.EncryptionConfiguration{
					HealthChecks: []healthz.HealthChecker{
						&mockHealthChecker{
							pluginName: "valid-plugin",
							err:        nil,
						},
						&mockHealthChecker{
							pluginName: "another-valid-plugin",
							err:        nil,
						},
					},
					// hash of initial "testdata/ec_config.yaml" config file before reloading
					EncryptionFileContentHash: "6bc9f4aa2e5587afbb96074e1809550cbc4de3cc3a35717dac8ff2800a147fd3",
				}, nil
			},
		},
		{
			name:                     "when invalid health check URL is provided previous config shouldn't be changed",
			ecFilePath:               "testdata/another_ec_config.yaml",
			apiServerID:              "test-apiserver",
			validateECFileHash:       true,
			validateTransformerClose: true,
			mockLoadEncryptionConfig: func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error) {
				return &encryptionconfig.EncryptionConfiguration{
					HealthChecks: []healthz.HealthChecker{
						&mockHealthChecker{
							pluginName: "invalid\nname",
							err:        nil,
						},
					},
					// hash of initial "testdata/ec_config.yaml" config file before reloading
					EncryptionFileContentHash: "6bc9f4aa2e5587afbb96074e1809550cbc4de3cc3a35717dac8ff2800a147fd3",
				}, nil
			},
		},
		{
			name:                     "when config is not updated transformers are closed correctly",
			ecFilePath:               "testdata/ec_config.yaml",
			apiServerID:              "test-apiserver",
			validateTransformerClose: true,
			mockLoadEncryptionConfig: func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error) {
				return &encryptionconfig.EncryptionConfiguration{
					HealthChecks: []healthz.HealthChecker{
						&mockHealthChecker{
							pluginName: "valid-plugin",
							err:        nil,
						},
					},
					// hash of initial "testdata/ec_config.yaml" config file before reloading
					EncryptionFileContentHash: "6bc9f4aa2e5587afbb96074e1809550cbc4de3cc3a35717dac8ff2800a147fd3",
				}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverCtx, closeServer := context.WithCancel(context.Background())
			defer closeServer()

			expectedFailureMetricValue := `
# HELP apiserver_encryption_config_controller_automatic_reload_failures_total [ALPHA] Total number of failed automatic reloads of encryption configuration split by apiserver identity.
# TYPE apiserver_encryption_config_controller_automatic_reload_failures_total counter
apiserver_encryption_config_controller_automatic_reload_failures_total{apiserver_id_hash="sha256:cd8a60cec6134082e9f37e7a4146b4bc14a0bf8a863237c36ec8fdb658c3e027"} 1
`
			expectedSuccessMetricValue := `
# HELP apiserver_encryption_config_controller_automatic_reload_success_total [ALPHA] Total number of successful automatic reloads of encryption configuration split by apiserver identity.
# TYPE apiserver_encryption_config_controller_automatic_reload_success_total counter
apiserver_encryption_config_controller_automatic_reload_success_total{apiserver_id_hash="sha256:cd8a60cec6134082e9f37e7a4146b4bc14a0bf8a863237c36ec8fdb658c3e027"} 1
`
			failureMetrics := []string{
				"apiserver_encryption_config_controller_automatic_reload_failures_total",
			}
			successMetrics := []string{
				"apiserver_encryption_config_controller_automatic_reload_success_total",
			}
			legacyregistry.Reset()

			// load initial encryption config
			encryptionConfiguration, err := encryptionconfig.LoadEncryptionConfig(
				serverCtx,
				"testdata/ec_config.yaml",
				true,
				test.apiServerID,
			)
			if err != nil {
				t.Fatalf("failed to load encryption config: %v", err)
			}

			d := NewDynamicEncryptionConfiguration(
				"test-controller",
				test.ecFilePath,
				encryptionconfig.NewDynamicTransformers(
					encryptionConfiguration.Transformers,
					encryptionConfiguration.HealthChecks[0],
					closeServer,
					encryptionConfiguration.KMSCloseGracePeriod,
				),
				encryptionConfiguration.EncryptionFileContentHash,
				test.apiServerID,
			)

			var testCtx context.Context
			var testEC *encryptionconfig.EncryptionConfiguration
			var loadCalls int
			d.loadEncryptionConfig = func(ctx context.Context, filePath string, enableEncryption bool, apiServerID string) (*encryptionconfig.EncryptionConfiguration, error) {
				loadCalls++
				testCtx = ctx
				ec, err := test.mockLoadEncryptionConfig(ctx, filePath, enableEncryption, apiServerID)
				testEC = ec
				return ec, err
			}

			d.queue = &mockWorkQueue{
				cancel: closeServer,
			}

			d.Run(serverCtx)

			if test.validateECFileHash {
				if d.lastLoadedEncryptionConfigHash != testEC.EncryptionFileContentHash && loadCalls == 1 {
					t.Fatalf("expected encryption config hash %q but got %q", testEC.EncryptionFileContentHash, d.lastLoadedEncryptionConfigHash)
				}
			}

			if test.validateTransformerClose {
				select {
				case <-time.After(10 * time.Second):
					t.Fatalf("ctx is expected to be Done but it is not")
				case <-testCtx.Done():
					// transformers are closed when closeTransformer's CancelFunc is called.
					// a successful call to closeTransformers will close its context's Done channel, indicating successful closure.
				}
			}

			if test.validateFailureMetric {
				if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedFailureMetricValue), failureMetrics...); err != nil {
					t.Fatalf("failed to validate failure metric: %v", err)
				}
			}

			if test.validateSuccessMetric {
				if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedSuccessMetricValue), successMetrics...); err != nil {
					t.Fatalf("failed to validate success metric: %v", err)
				}
			}
		})
	}
}

// mock workqueue.RateLimitingInterface
type mockWorkQueue struct {
	workqueue.RateLimitingInterface // will panic if any unexpected method is called
	count                           atomic.Uint64
	cancel                          func()
}

var _ workqueue.RateLimitingInterface = &mockWorkQueue{}

func (m *mockWorkQueue) Done(item interface{}) {
	m.count.Add(1)
	m.cancel()
}

func (m *mockWorkQueue) Get() (item interface{}, shutdown bool) {
	return nil, m.count.Load() > 0
}

func (m *mockWorkQueue) Add(item interface{})            {}
func (m *mockWorkQueue) ShutDown()                       {}
func (m *mockWorkQueue) AddRateLimited(item interface{}) {}

type mockHealthChecker struct {
	pluginName string
	err        error
}

func (m *mockHealthChecker) Check(req *http.Request) error {
	return m.err
}

func (m *mockHealthChecker) Name() string {
	return m.pluginName
}
