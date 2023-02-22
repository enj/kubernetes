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
	t.Parallel()

	for _, tt := range []struct {
		name string
		f    func(*testing.T, *EncryptedKeyToTransformer)
	}{
		{
			name: "simple set",
			f: func(t *testing.T, c *EncryptedKeyToTransformer) {
				transformer := testTransformer()

				c.Set([]byte("e-dek-001"), "/a/path/to/pandas", transformer)

				assertCacheMatches(t, c,
					map[string]*cacheRecord{
						"e-dek-001": {
							hash:        "e-dek-001",
							transformer: transformer,
						},
					},
					map[string]*cacheRecord{
						"/a/path/to/pandas": {
							hash:        "e-dek-001",
							transformer: transformer,
						},
					},
					map[string]string{
						"e-dek-001": "/a/path/to/pandas",
					},
					map[string]string{
						"/a/path/to/pandas": "e-dek-001",
					},
				)
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := testContext(t)

			c := newCache(ctx, 5, 4, time.Second, testKeyFunc)

			assertCacheMatches(t, c, nil, nil, nil, nil)

			tt.f(t, c)
		})
	}
}

func assertCacheMatches(t *testing.T, c *EncryptedKeyToTransformer,
	wantKeyCache, wantNameCache map[string]*cacheRecord,
	wantEqKeyCache, wantEqNameCache map[string]string) {
	t.Helper()

	gotKeyCache := dumpMap(&c.keyToTransformerCache)
	if diff := cmp.Diff(wantKeyCache, gotKeyCache,
		cmp.AllowUnexported(cacheRecord{}),
		cmp.FilterPath(func(path cmp.Path) bool {
			return path.String() == "transformer.block" // TODO remove this filter
		}, cmp.Ignore())); len(diff) > 0 {
		t.Errorf("key cache has unexpected diff (-want +got):\n%s", diff)
	}

	gotNameCache := dumpMap(&c.nameToTransformerCache)
	if diff := cmp.Diff(wantNameCache, gotNameCache,
		cmp.AllowUnexported(cacheRecord{}),
		cmp.FilterPath(func(path cmp.Path) bool {
			return path.String() == "transformer.block"
		}, cmp.Ignore())); len(diff) > 0 {
		t.Errorf("name cache has unexpected diff (-want +got):\n%s", diff)
	}

	gotEqKeyCache := mapKeysWithEqualValues(gotKeyCache, gotNameCache)
	if diff := cmp.Diff(wantEqKeyCache, gotEqKeyCache); len(diff) > 0 {
		t.Errorf("equal key cache values has unexpected diff (-want +got):\n%s", diff)
	}

	gotEqNameCache := mapKeysWithEqualValues(gotNameCache, gotKeyCache)
	if diff := cmp.Diff(wantEqNameCache, gotEqNameCache); len(diff) > 0 {
		t.Errorf("equal name cache values has unexpected diff (-want +got):\n%s", diff)
	}
}

func dumpMap(m *sync.Map) map[string]*cacheRecord {
	out := map[string]*cacheRecord{}
	m.Range(func(key, value any) bool {
		out[key.(string)] = value.(*cacheRecord)
		return true
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func mapKeysWithEqualValues(a, b map[string]*cacheRecord) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		for kk, vv := range b {
			if v == vv {
				out[k] = kk
			}
		}
	}
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
