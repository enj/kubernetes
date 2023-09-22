/*
Copyright 2023 The Kubernetes Authors.

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

package controlplane

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/storage/etcd3"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/kubernetes"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/klog/v2"
	kubeapiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/test/integration/framework"
	"k8s.io/utils/ptr"
)

func TestStorageMigrationWithWatchList(t *testing.T) {
	klog.SetOutput(io.Discard)
	klog.LogToStderr(false)

	defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.WatchList, true)()

	etcd3.DefaultWatcherMaxLimit = 1 // increase the chance of compaction impacting streaming watch

	storageConfig := framework.SharedEtcd()
	storageConfig.CompactionInterval = time.Second // compact constantly

	result := kubeapiservertesting.StartTestServerOrDie(t, nil, nil, storageConfig)
	t.Cleanup(result.TearDownFn)

	client, err := kubernetes.NewForConfig(result.ClientConfig)
	if err != nil {
		t.Fatal(err)
	}

	const testNamespace = "default"
	const dataLen = 10_000

	ctx := context.TODO()

	secretStorage := client.CoreV1().Secrets(testNamespace)

	for i := 0; i < dataLen; i++ {
		_, err := secretStorage.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test-secret-%d", i),
				Namespace: testNamespace,
			},
			Data: map[string][]byte{
				"lots_of_data": bytes.Repeat([]byte{1, 3, 3, 7}, 2),
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Log("starting watch")

	ticker := time.NewTicker(100 * time.Millisecond)
	t.Cleanup(ticker.Stop)

	var continue_ string
	var count int
	names := sets.NewString()
outer:
	for {
		t.Log(continue_)

		w, err := secretStorage.Watch(ctx, metav1.ListOptions{
			AllowWatchBookmarks:  true,
			ResourceVersion:      "-1",
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
			Continue:             continue_,
			SendInitialEvents:    ptr.To(true),
		})
		if err != nil {
			t.Fatal(err)
		}

		for event := range w.ResultChan() {
			switch event.Type {
			case watch.Error:
				w.Stop()

				status, ok := event.Object.(*metav1.Status)
				if !ok {
					t.Fatalf("unexpected status: %v", event.Object)
				}

				if status.Reason != metav1.StatusReasonExpired || len(status.ListMeta.Continue) == 0 {
					t.Fatalf("unexpected status: %v", event.Object)
				}

				continue_ = status.ListMeta.Continue

				continue outer

			case watch.Bookmark:
				w.Stop()

				secret, ok := event.Object.(*corev1.Secret)
				if !ok {
					t.Fatalf("unexpected bookmark: %v", event.Object)
				}

				if secret.ObjectMeta.Annotations["k8s.io/initial-events-end"] != "true" {
					t.Fatalf("unexpected bookmark: %v", event.Object)
				}

				break outer

			default:
				count++

				secret, ok := event.Object.(*corev1.Secret)
				if !ok {
					t.Fatalf("unexpected secret: %v", event.Object)
				}

				names.Insert(secret.Name)

				// pretend the actual storage migration work is here, for now we just log every so often
				select {
				case <-ticker.C:
					t.Log(count, event.Object)
				default:
					// skip logging
				}
			}
		}
	}

	t.Log("end", count)

	if n := len(names); n != dataLen {
		t.Errorf("invalid list, want %d, got %d", dataLen, n)
	}

	if len(continue_) == 0 {
		t.Error("expected at least one inconsistent continue, but got none")
	}
}
