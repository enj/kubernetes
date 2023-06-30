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

package aes

import (
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"
)

type dataString string

func (d dataString) AuthenticatedData() []byte { return []byte(d) }

func Test_simpleCache(t *testing.T) {
	info1 := []byte{1}
	info2 := []byte{2}
	key1 := dataString("1")
	key2 := dataString("2")
	gcm1 := &gcm{info: info1}
	gcm2 := &gcm{info: info2}

	tests := []struct {
		name string
		test func(*testing.T, *simpleCache, *clocktesting.FakeClock)
	}{
		{
			name: "get from empty",
			test: func(t *testing.T, cache *simpleCache, clock *clocktesting.FakeClock) {
				got := cache.get(info1, key1)
				gcmPtrEquals(t, nil, got)
				cacheLenEquals(t, cache, 0)
			},
		},
		{
			name: "get after set",
			test: func(t *testing.T, cache *simpleCache, clock *clocktesting.FakeClock) {
				cache.set(key1, gcm1)
				got := cache.get(info1, key1)
				gcmPtrEquals(t, gcm1, got)
				cacheLenEquals(t, cache, 1)
			},
		},
		{
			name: "get after set but with different info",
			test: func(t *testing.T, cache *simpleCache, clock *clocktesting.FakeClock) {
				cache.set(key1, gcm1)
				got := cache.get(info2, key1)
				gcmPtrEquals(t, nil, got)
				cacheLenEquals(t, cache, 1)
			},
		},
		{
			name: "expired get after set",
			test: func(t *testing.T, cache *simpleCache, clock *clocktesting.FakeClock) {
				cache.set(key1, gcm1)
				clock.Step(time.Hour)
				got := cache.get(info1, key1)
				gcmPtrEquals(t, gcm1, got)
				cacheLenEquals(t, cache, 1)
			},
		},
		{
			name: "expired get after GC",
			test: func(t *testing.T, cache *simpleCache, clock *clocktesting.FakeClock) {
				cache.set(key1, gcm1)
				clock.Step(time.Hour)
				cacheLenEquals(t, cache, 1)
				cache.set(key2, gcm2) // unrelated set to make GC run
				got := cache.get(info1, key1)
				gcmPtrEquals(t, nil, got)
				cacheLenEquals(t, cache, 1)
			},
		},
		{
			name: "multiple sets for same key",
			test: func(t *testing.T, cache *simpleCache, clock *clocktesting.FakeClock) {
				cache.set(key1, gcm1)
				cacheLenEquals(t, cache, 1)
				cache.set(key1, gcm2)
				cacheLenEquals(t, cache, 1)

				got11 := cache.get(info1, key1)
				gcmPtrEquals(t, nil, got11)

				got21 := cache.get(info2, key1)
				gcmPtrEquals(t, gcm2, got21)

				got12 := cache.get(info1, key2)
				gcmPtrEquals(t, nil, got12)

				got22 := cache.get(info2, key2)
				gcmPtrEquals(t, nil, got22)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clock := clocktesting.NewFakeClock(time.Now())
			cache := newSimpleCache(clock, 10*time.Second)
			tt.test(t, cache, clock)
		})
	}
}

func gcmPtrEquals(t *testing.T, want, got *gcm) {
	t.Helper()

	if want != got {
		t.Errorf("gcm transformers are not pointer equivalent")
	}
}

func cacheLenEquals(t *testing.T, cache *simpleCache, want int) {
	t.Helper()

	if got := cache.cache.Len(); want != got {
		t.Errorf("unexpected cache len: want %d, got %d", want, got)
	}
}
