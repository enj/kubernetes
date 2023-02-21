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

package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"k8s.io/kms/pkg/encrypt/aes"
	"k8s.io/kms/pkg/value"
)

func TestSet(t *testing.T) {
	ctx := testContext(t)

	c := newCache(ctx, 5, 4, time.Second, testKeyFunc)

	assertCacheMatches(t, c, nil, nil)

	transformer := testTransformer()

	c.Set([]byte("hello"), "panda", transformer)

	assertCacheMatches(t, c,
		map[string]cacheRecord{
			"hello": {
				hash:        "hello",
				transformer: transformer,
			},
		},
		map[string]cacheRecord{
			"panda": {
				hash:        "hello",
				transformer: transformer,
			},
		},
	)
}

func assertCacheMatches(t *testing.T, c *EncryptedKeyToTransformer, wantKeyCache, wantNameCache map[string]cacheRecord) {
	t.Helper()

	if diff := cmp.Diff(wantKeyCache, dumpMap(&c.keyToTransformerCache)); len(diff) > 0 {
		t.Errorf("key cache has unexpected diff (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(wantNameCache, dumpMap(&c.nameToTransformerCache)); len(diff) > 0 {
		t.Errorf("name cache has unexpected diff (-want +got):\n%s", diff)
	}
}

func dumpMap(m *sync.Map) map[string]cacheRecord {
	out := map[string]cacheRecord{}
	m.Range(func(key, value any) bool {
		out[key.(string)] = *(value.(*cacheRecord)) // TODO need to check for pointer equality too
		return true
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func testKeyFunc(keyBytes []byte) string { return string(keyBytes) }

func testTransformer() value.Transformer { return aes.NewGCMTransformer(nil) }

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}
