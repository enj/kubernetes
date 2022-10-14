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

package transformation

import (
	"context"
	"testing"
	"time"

	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/kubernetes/test/integration/etcd"
)

func createResources(t *testing.T, test *transformTest) {
	test.dynamicInterface = dynamic.NewForConfigOrDie(test.kubeAPIServer.ClientConfig)
	switch test.resource {
	case "pods":
		_, err := test.createPod(test.name, test.namespaceName, test.dynamicInterface)
		if err != nil {
			t.Fatalf("Failed to create test pod, error: %v, name: %s, ns: %s", err, test.name, test.namespaceName)
		}
	case "configmaps":
		_, err := test.createConfigMap(test.name, test.namespaceName)
		if err != nil {
			t.Fatalf("Failed to create test configmap, error: %v, name: %s, ns: %s", err, test.name, test.namespaceName)
		}
	default:
		// the storage registry for CRs is dynamic so create one to exercise the wiring
		etcd.CreateTestCRDs(t, apiextensionsclientset.NewForConfigOrDie(test.kubeAPIServer.ClientConfig), false, etcd.GetCustomResourceDefinitionData()...)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)

		gvr := schema.GroupVersionResource{Group: test.group, Version: test.version, Resource: test.resource}
		data := etcd.GetEtcdStorageData()[gvr]
		stub := data.Stub
		dynamicClient, obj, err := etcd.JSONToUnstructured(stub, test.namespaceName, &meta.RESTMapping{
			Resource:         gvr,
			GroupVersionKind: gvr.GroupVersion().WithKind(test.kind),
			Scope:            meta.RESTScopeRoot,
		}, test.dynamicInterface)
		if err != nil {
			t.Fatal(err)
		}
		_, err = dynamicClient.Create(ctx, obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dynamicClient.Get(ctx, obj.GetName(), metav1.GetOptions{}); err != nil {
			t.Fatalf("object should exist: %v", err)
		}
	}
}
func TestEncryptSupportedForAllResourceTypes(t *testing.T) {
	// check resources provided by the three servers that we have wired together
	// - pods and configmaps from KAS
	// - CRDs and CRs from API extensions
	// - API services from aggregator
	encryptionConfig := `
kind: EncryptionConfiguration
apiVersion: apiserver.config.k8s.io/v1
resources:
- resources:
  - pods
  - configmaps
  - customresourcedefinitions.apiextensions.k8s.io
  - pandas.awesome.bears.com
  - apiservices.apiregistration.k8s.io
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: c2VjcmV0IGlzIHNlY3VyZQ==
`

	var testCases = []struct {
		group     string
		version   string
		kind      string
		resource  string
		name      string
		namespace string
	}{
		{"", "v1", "ConfigMap", "configmaps", "cm1", testNamespace},
		{"apiextensions.k8s.io", "v1", "CustomResourceDefinition", "customresourcedefinitions", "pandas.awesome.bears.com", ""},
		{"awesome.bears.com", "v1", "Panda", "pandas", "cr3panda", ""},
		{"apiregistration.k8s.io", "v1", "APIService", "apiservices", "as2.foo.com", ""},
		{"", "v1", "Pod", "pods", "pod1", testNamespace},
	}
	for _, tt := range testCases {
		test, err := newTransformTest(t, encryptionConfig)
		if err != nil {
			t.Fatalf("failed to start KUBE API Server with encryptionConfig\n %s, error: %v", encryptionConfig, err)
			test.cleanUp()
			continue
		}
		test.group = tt.group
		test.version = tt.version
		test.kind = tt.kind
		test.resource = tt.resource
		test.name = tt.name
		test.namespaceName = tt.namespace
		createResources(t, test)
		test.run(unSealWithCBCTransformer, aesCBCPrefix)
		test.cleanUp()
	}
}
