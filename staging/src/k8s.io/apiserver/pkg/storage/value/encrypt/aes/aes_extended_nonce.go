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
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/utils/clock"
)

const (
	// cacheTTL is the TTL of KDF cache entries.  We assume that the value.Context.AuthenticatedData
	// for every call is the etcd storage path of the associated resource, and use that as the primary
	// cache key (with a secondary check that confirms that the gcm.info matches).  Thus if a client
	// is constantly creating resources with new names (and thus new paths), they will keep adding new
	// entries to the cache for up to this TTL before the GC logic starts deleting old entries.  Each
	// entry is ~300 bytes in size, so even a malicious client will be bounded in the overall memory
	// it can consume.
	cacheTTL = 10 * time.Minute

	derivedKeySizeExtendedNonceGCM = commonSize
	infoSizeExtendedNonceGCM
	minSeedSizeExtendedNonceGCM
)

// NewKDFExtendedNonceGCMTransformerFromSeedUnsafe is the same as NewGCMTransformer but trades storage,
// memory and CPU to work around the limitations of AES-GCM's 12 byte nonce size.  It is marked
// as unsafe because it assumes that the input seed is a cryptographically strong key that is at least
// 32 bytes in length.  Callers that do need to supply a specific seed must use
// NewKDFExtendedNonceGCMTransformerWithUniqueSeed instead to guarantee that a secure seed is used.
// Unlike NewGCMTransformer, this function is immune to the birthday attack because a new key is generated
// per encryption via a key derivation function: KDF(seed, random_bytes) -> key.  The derived key is
// only used once as an AES-GCM key with a random 12 byte nonce.  This avoids any concerns around
// cryptographic wear out (by either number of encryptions or the amount of data being encrypted).
// No specific rotation schedule is required for the seed.  NewKDFExtendedNonceGCMTransformerWithUniqueSeed
// and this function encrypt and decrypt data in a compatible way (so the output of one can be used
// as the input to the other, and vice versa).
func NewKDFExtendedNonceGCMTransformerFromSeedUnsafe(seed []byte) (value.Transformer, error) {
	if seedLen := len(seed); seedLen < minSeedSizeExtendedNonceGCM {
		return nil, fmt.Errorf("invalid seed length %d used for key generation", seedLen)
	}
	return &extendedNonceGCM{
		seed:  seed,
		cache: newSimpleCache(clock.RealClock{}, cacheTTL),
	}, nil
}

// NewKDFExtendedNonceGCMTransformerWithUniqueSeed is the same as NewKDFExtendedNonceGCMTransformerFromSeedUnsafe
// but it handles the seed generation for the caller.  Whenever a new seed is needed (for example,
// during key rotation), this function should be used over the caller generating a new seed.  This
// function is considered safe because there is no input that a caller could make a mistake with,
// and the output transformer has the properties of AES-GCM without the nonce size limitations.
// A new random seed is generated and returned on every invocation of this function.  If the seed is
// stored and retrieved at a later point, it can be passed to NewKDFExtendedNonceGCMTransformerFromSeedUnsafe
// to construct a transformer capable of decrypting values encrypted by this transformer;
// reusing the seed returned from this function is safe to do over time and across process restarts.
func NewKDFExtendedNonceGCMTransformerWithUniqueSeed() (value.Transformer, []byte, error) {
	seed, err := generateKey(minSeedSizeExtendedNonceGCM)
	if err != nil {
		return nil, nil, err
	}
	transformer, err := NewKDFExtendedNonceGCMTransformerFromSeedUnsafe(seed)
	if err != nil {
		return nil, nil, err
	}
	return transformer, seed, nil
}

type extendedNonceGCM struct {
	seed  []byte
	cache *simpleCache
}

func (e *extendedNonceGCM) TransformFromStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, bool, error) {
	if len(data) < infoSizeExtendedNonceGCM {
		return nil, false, errors.New("the stored data was shorter than the required size")
	}

	info := data[:infoSizeExtendedNonceGCM]

	transformer, err := e.derivedKeyTransformer(info, dataCtx, false)
	if err != nil {
		return nil, false, fmt.Errorf("failed to derive read key from KDF: %w", err)
	}

	return transformer.TransformFromStorage(ctx, data, dataCtx)
}

func (e *extendedNonceGCM) TransformToStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, error) {
	info := make([]byte, infoSizeExtendedNonceGCM)
	if err := randomNonce(info); err != nil {
		return nil, fmt.Errorf("failed to generate info for KDF: %w", err)
	}

	transformer, err := e.derivedKeyTransformer(info, dataCtx, true)
	if err != nil {
		return nil, fmt.Errorf("failed to derive write key from KDF: %w", err)
	}

	return transformer.TransformToStorage(ctx, data, dataCtx)
}

func (e *extendedNonceGCM) derivedKeyTransformer(info []byte, dataCtx value.Context, write bool) (value.Transformer, error) {
	if !write { // no need to check cache on write since we always generate a new transformer
		if transformer := e.cache.get(info, dataCtx); transformer != nil {
			return transformer, nil
		}

		// on read, this is a subslice of a much larger slice and we do not want to hold onto that larger slice
		info = bytes.Clone(info)
	}

	key, err := e.sha256KDFExpandOnly(info)
	if err != nil {
		return nil, fmt.Errorf("failed to KDF expand seed with info: %w", err)
	}

	transformer, err := newGCMTransformerWithInfo(key, info)
	if err != nil {
		return nil, fmt.Errorf("failed to build transformer with KDF derived key: %w", err)
	}

	e.cache.set(dataCtx, transformer)

	return transformer, nil
}

func (e *extendedNonceGCM) sha256KDFExpandOnly(info []byte) ([]byte, error) {
	kdf := hkdf.Expand(sha256.New, e.seed, info)

	derivedKey := make([]byte, derivedKeySizeExtendedNonceGCM)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to read a derived key from KDF: %w", err)
	}

	return derivedKey, nil
}

func newGCMTransformerWithInfo(key, info []byte) (*gcm, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	transformer, err := newGCMTransformerWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	aead := transformer.aead
	transformer.aead = &aeadWithInfoAndRandomNonce{aead: aead, info: info}

	return transformer, nil
}

var _ cipher.AEAD = &aeadWithInfoAndRandomNonce{}

type aeadWithInfoAndRandomNonce struct {
	aead cipher.AEAD
	info []byte
}

func (a *aeadWithInfoAndRandomNonce) NonceSize() int {
	return 0 // nonce generation is internal to this AEAD wrapper, the caller does not control it
}

func (a *aeadWithInfoAndRandomNonce) Overhead() int {
	return a.aead.Overhead() + len(a.info) + a.aead.NonceSize()
}

func (a *aeadWithInfoAndRandomNonce) Seal(dst, _, plaintext, additionalData []byte) []byte {
	if cap(dst) != a.Overhead()+len(plaintext) {
		panic("aes-gcm detected invalid destination buffer capacity")
	}

	infoSize := len(a.info)
	nonceEnd := infoSize + a.aead.NonceSize()

	dst = append(dst, a.info...)

	if err := randomNonce(dst[infoSize:nonceEnd]); err != nil {
		panic(fmt.Errorf("failed to generate random nonce: %w", err))
	}

	cipherText := a.aead.Seal(dst[nonceEnd:nonceEnd], dst[infoSize:nonceEnd], plaintext, additionalData)

	return dst[:nonceEnd+len(cipherText)]
}

func (a *aeadWithInfoAndRandomNonce) Open(dst, _, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < a.Overhead() {
		return nil, errors.New("the stored data is too short")
	}

	if !bytes.HasPrefix(ciphertext, a.info) {
		return nil, errors.New("the stored data is missing the required info prefix")
	}

	infoSize := len(a.info)
	nonceEnd := infoSize + a.aead.NonceSize()

	return a.aead.Open(dst, ciphertext[infoSize:nonceEnd], ciphertext[nonceEnd:], additionalData)
}
