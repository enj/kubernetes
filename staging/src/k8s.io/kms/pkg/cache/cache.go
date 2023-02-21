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
	"time"
	"unsafe"

	"k8s.io/kms/pkg/value"
)

const (
	// if the cache size is less than this value, we will not GC.
	// this means that the cache will take at least 152 MB before
	// we start to shrink it back down.
	// TODO fix this comment
	minCacheSize = 1 << 18

	gcInterval       = time.Minute
	gcBuckets        = 1 << 5
	gcDelCount       = minCacheSize / gcBuckets
	cacheSizeAfterGC = minCacheSize - gcDelCount
)

// EncryptedKeyToTransformer TODO comment
type EncryptedKeyToTransformer struct {
	// encrypted key bytes -> transformer
	// each key is 32 bytes (since we hash it with SHA-256)
	// each value is 120 bytes for AES: 2 * (32 + 28)
	// since the map key is expected to be random noise,
	// we never expect a map key to be used more than once.
	keyToTransformerCache sync.Map

	// TODO consider etcd path -> key bytes -> transformer
	// nameToTransformerCache is guaranteed to always be either smaller or the exact same
	// size as keyToTransformerCache because names will have duplicates whereas keys will not.
	// thus we do not need to track the size of this cache in a separate manner.
	nameToTransformerCache sync.Map

	minSize int
	// hashPool is a per cache pool of hash.Hash (to avoid allocations from building the Hash)
	// SHA-256 is used to prevent collisions
	hashPool sync.Pool

	hashes chan hashAndName
}

type cacheRecord struct {
	hash        string
	transformer value.Transformer
}

type hashAndName struct {
	hash string
	name string
}

// TODO gave cache a name for metrics
// TODO make a NewBig and NewSmall
func New(ctx context.Context) *EncryptedKeyToTransformer {
	return newCache(ctx, minCacheSize, cacheSizeAfterGC, gcInterval)
}

func newCache(ctx context.Context, minSize, sizeAfterGC int, interval time.Duration) *EncryptedKeyToTransformer {
	e := &EncryptedKeyToTransformer{
		minSize: minSize,
		hashPool: sync.Pool{
			New: func() interface{} {
				return sha256.New()
			},
		},
		hashes: make(chan hashAndName, minSize-sizeAfterGC), // TODO should this be buffered or not?
	}
	go e.gcLoop(ctx, sizeAfterGC, interval) // TODO maybe better as a Run?
	return e
}

func (e *EncryptedKeyToTransformer) Get(key []byte, name string) value.Transformer {
	// TODO metrics record cache hit+miss

	keyHash := e.keyFunc(key)

	record, ok := e.keyToTransformerCache.Load(keyHash)
	if ok {
		return record.(*cacheRecord).transformer
	}

	// name is optional, nothing to lookup if it is not provided
	if len(name) == 0 {
		return nil
	}

	nameLookup, ok := e.nameToTransformerCache.Load(name)
	if !ok {
		return nil
	}
	nameLookupRecord := nameLookup.(*cacheRecord)

	if nameLookupRecord.hash != keyHash {
		return nil
	}

	return nameLookupRecord.transformer
}

func (e *EncryptedKeyToTransformer) Set(key []byte, name string, transformer value.Transformer) {
	if len(key) == 0 {
		panic("key must not be empty")
	}
	if transformer == nil {
		panic("transformer must not be nil")
	}

	keyHash := e.keyFunc(key)

	// store pointer so we can compare the address between the two caches on GC later
	record := &cacheRecord{hash: keyHash, transformer: transformer}

	if _, loaded := e.keyToTransformerCache.LoadOrStore(keyHash, record); loaded {
		panic("duplicate key") // TODO what is best here?
	}

	// name is optional, only store a nameRecord if we need to
	if len(name) > 0 {
		// names are not required to be unique so we do not checked for loaded here
		// TODO hash name after https://github.com/kubernetes/kubernetes/pull/115935 is fixed
		e.nameToTransformerCache.Store(name, record)
	}

	// in a separate go routine, inform the GC about this hash
	// we always do this at the end, after both maps have recorded the insertion
	go func() {
		e.hashes <- hashAndName{hash: keyHash, name: name}
	}()
}

func (e *EncryptedKeyToTransformer) gcLoop(ctx context.Context, sizeAfterGC int, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()

	var hashes list.List
	for done := e.gcIter(ctx, sizeAfterGC, t, &hashes); !done; {
	}
	// TODO drain e.hashes to prevent any go routine leaks on exit
}

func (e *EncryptedKeyToTransformer) gcIter(ctx context.Context, sizeAfterGC int, ticker *time.Ticker, hashes *list.List) bool {
	select {
	case <-ctx.Done():
		return true
	case <-ticker.C:
		if hashes.Len() <= e.minSize {
			// TODO metrics record no GC
			return false // nothing to do, approximate cache size is still too small
		}
		// TODO metrics record GC run start with start size (and/or percentage)
		e.deleteOldKeys(ctx, sizeAfterGC, hashes)
		// TODO metrics record GC run stop with stop size (and/or percentage)
	case keyHash := <-e.hashes:
		hashes.PushBack(keyHash)
	}
	return false
}

func (e *EncryptedKeyToTransformer) deleteOldKeys(ctx context.Context, sizeAfterGC int, hashes *list.List) {
	for keepDeleting := hashes.Len() > sizeAfterGC; keepDeleting; {
		select {
		case <-ctx.Done():
			return // stop deleting early
		default:
		}

		key := hashes.Remove(hashes.Front()).(hashAndName)

		keyRecord, keyRecordLoaded := e.keyToTransformerCache.LoadAndDelete(key.hash)
		if !keyRecordLoaded {
			panic("unexpected missing key") // TODO what is best here?
		}

		if len(key.name) == 0 {
			continue // use of the name cache is optional
		}

		nameRecord, nameRecordLoaded := e.nameToTransformerCache.LoadAndDelete(key.name)
		if !nameRecordLoaded { // TODO metrics around cache miss/hit here?
			continue // duplicate names are possible so this could have already been deleted
		}

		if keyRecord == nameRecord {
			continue // deletion from name cache is valid because the values have the same pointer address
		}

		// otherwise, we put the value for the name cache back, unless Set puts a new value before us
		e.nameToTransformerCache.LoadOrStore(key.name, nameRecord) // TODO loaded metric for this
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
