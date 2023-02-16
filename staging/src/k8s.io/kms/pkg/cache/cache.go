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
	"container/list"
	"context"
	"crypto/sha256"
	"hash"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"k8s.io/kms/pkg/value"
)

const (
	// if the cache size is less than this value, we will not GC.
	// this means that the cache will take at least 152 MB before
	// we start to shrink it back down.
	size       = 1 << 20
	gcInterval = 5 * time.Minute
	gcBucket   = 1 << 5
)

// EncryptedKeyToTransformer TODO comment
type EncryptedKeyToTransformer struct {
	// encrypted key bytes -> transformer
	// each key is 32 bytes (since we hash it with SHA-256)
	// each value is 120 bytes for AES: 2 * (32 + 28)
	// since the map key is expected to be random noise,
	// we never expect a map key to be used more than once.
	// TODO consider etcd path -> key bytes -> transformer
	cache sync.Map
	size  atomic.Int64

	minSize int64
	// hashPool is a per cache pool of hash.Hash (to avoid allocations from building the Hash)
	// SHA-256 is used to prevent collisions
	hashPool sync.Pool

	hashes chan string
}

func New(ctx context.Context) *EncryptedKeyToTransformer {
	return newCache(ctx, size, gcBucket, gcInterval)
}

func newCache(ctx context.Context, minSize, bucket int64, interval time.Duration) *EncryptedKeyToTransformer {
	if minSize%bucket != 0 {
		panic("invalid GC bucket size")
	}
	delCount := minSize / bucket

	e := &EncryptedKeyToTransformer{
		minSize: minSize,
		hashPool: sync.Pool{
			New: func() interface{} {
				return sha256.New()
			},
		},
		hashes: make(chan string, delCount), // TODO should this be buffered or not?
	}
	go e.gcLoop(ctx, delCount, interval) // TODO maybe better as a Run?
	return e
}

func (e *EncryptedKeyToTransformer) Get(key []byte) value.Transformer {
	record, ok := e.cache.Load(e.keyFunc(key))
	if !ok {
		return nil
	}
	return record.(value.Transformer)
}

func (e *EncryptedKeyToTransformer) Set(key []byte, transformer value.Transformer) {
	if len(key) == 0 {
		panic("key must not be empty")
	}
	if transformer == nil {
		panic("transformer must not be nil")
	}
	e.size.Add(1)
	keyHash := e.keyFunc(key)
	if _, loaded := e.cache.LoadOrStore(keyHash, transformer); loaded {
		panic("duplicate key") // TODO what is best here?
	}
	// in a separate go routine, inform the GC about this hash
	go func() {
		e.hashes <- keyHash
	}()
}

func (e *EncryptedKeyToTransformer) gcLoop(ctx context.Context, delCount int64, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()

	var hashes list.List
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if e.size.Load() <= e.minSize {
				continue // nothing to do, cache is still too small
			}
			e.gc(ctx, delCount, &hashes)
		case keyHash := <-e.hashes:
			hashes.PushBack(keyHash)
		}
	}
}

func (e *EncryptedKeyToTransformer) gc(ctx context.Context, delCount int64, hashes *list.List) {
	var count int64
	for {
		select {
		case <-ctx.Done():
			return // stop deleting early
		default:
		}

		key := hashes.Remove(hashes.Front())
		if _, loaded := e.cache.LoadAndDelete(key); !loaded {
			panic("unexpected missing key") // TODO what is best here?
		}

		// always delete at least delCount entries and, if needed, keep deleting until we reach minSize
		newSize := e.size.Add(-1)
		count++
		if keepDeleting := newSize > e.minSize || count < delCount; !keepDeleting {
			return
		}
	}
}

// keyFunc generates a string key by hashing the inputs.
// This lowers the memory requirement of the cache.
func (e *EncryptedKeyToTransformer) keyFunc(keyBytes []byte) string {
	h := e.hashPool.Get().(hash.Hash)
	h.Reset()

	if _, err := h.Write(keyBytes); err != nil {
		panic(err) // Write() on hash never fails
	}
	key := toString(h.Sum(nil)) // skip base64 encoding to save an allocation
	e.hashPool.Put(h)

	return key
}

// toString performs unholy acts to avoid allocations
func toString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
