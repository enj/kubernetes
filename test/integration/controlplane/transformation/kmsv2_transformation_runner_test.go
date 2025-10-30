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

package transformation

import "testing"

// TestKMSv2Runner manually calls all the top level test funcs in the
// kmsv2_transformation_test_funcs.go file as they are no longer automatically
// run because the file does not end in _test.go.  This is required to
// allow those funcs to be imported from other packages which allows us to
// split up global state across different test packages that can then be
// executed in parallel.
func TestKMSv2Runner(t *testing.T) {
	t.Run("TestDefaultValues", TestDefaultValues)
	t.Run("TestKMSv2ProviderKeyIDStaleness", TestKMSv2ProviderKeyIDStaleness)
	t.Run("TestKMSv2ProviderDEKSourceReuse", TestKMSv2ProviderDEKSourceReuse)
	t.Run("TestKMSv2Healthz", TestKMSv2Healthz)
	t.Run("TestKMSv2SingleService", TestKMSv2SingleService) // TODO also move this test
	t.Run("TestKMSv2FeatureFlag", TestKMSv2FeatureFlag)
	t.Run("TestKMSv2ProviderLegacyData", TestKMSv2ProviderLegacyData) // TODO also move this test

	// The following slow tests have been moved to their own sub package so that they can run in parallel
	// TestKMSv2Provider
}
