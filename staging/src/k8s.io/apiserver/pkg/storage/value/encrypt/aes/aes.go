/*
Copyright 2017 The Kubernetes Authors.

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

// Package aes transforms values for storage at rest using AES-GCM.
package aes

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"

	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

// commonSize is the length of various security sensitive byte slices such as encryption keys.
// Do not change this value.  It would be a backward incompatible change.
const commonSize = 32

// cacheTTL is the TTL of KDF cache entries.  We assume that the value.Context.AuthenticatedData
// for every call is the etcd storage path of the associated resource, and use that as the primary
// cache key (with a secondary check that confirms that the gcm.info matches).  Thus if a client
// is constantly creating resources with new names (and thus new paths), they will keep adding new
// entries to the cache for up to this TTL before the GC logic starts deleting old entries.  Each
// entry is ~300 bytes in size, so even a malicious client will be bounded in the overall memory
// it can consume.
const cacheTTL = 10 * time.Minute

type gcm struct {
	aead      cipher.AEAD
	nonceFunc func([]byte) error
	info      []byte
}

// NewGCMTransformer takes the given block cipher and performs encryption and decryption on the given data.
// It implements AEAD encryption of the provided values given a cipher.Block algorithm.
// The authenticated data provided as part of the value.Context method must match when the same
// value is set to and loaded from storage. In order to ensure that values cannot be copied by
// an attacker from a location under their control, use characteristics of the storage location
// (such as the etcd key) as part of the authenticated data.
//
// Because this mode requires a generated IV and IV reuse is a known weakness of AES-GCM, keys
// must be rotated before a birthday attack becomes feasible. NIST SP 800-38D
// (http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf) recommends using the same
// key with random 96-bit nonces (the default nonce length) no more than 2^32 times, and
// therefore transformers using this implementation *must* ensure they allow for frequent key
// rotation. Future work should include investigation of AES-GCM-SIV as an alternative to
// random nonces.
func NewGCMTransformer(block cipher.Block) (value.Transformer, error) {
	return newGCMTransformerWithInfo(block, nil)
}

func newGCMTransformerWithInfo(block cipher.Block, info []byte) (*gcm, error) {
	aead, err := newGCM(block)
	if err != nil {
		return nil, err
	}

	return &gcm{aead: aead, nonceFunc: randomNonce, info: info}, nil
}

// NewGCMTransformerWithUniqueKeyUnsafe is the same as NewGCMTransformer but is unsafe for general
// use because it makes assumptions about the key underlying the block cipher.  Specifically,
// it uses a 96-bit nonce where the first 32 bits are random data and the remaining 64 bits are
// a monotonically incrementing atomic counter.  This means that the key must be randomly generated
// on process startup and must never be used for encryption outside the lifetime of the process.
// Unlike NewGCMTransformer, this function is immune to the birthday attack and thus the key can
// be used for 2^64-1 writes without rotation.  Furthermore, cryptographic wear out of AES-GCM with
// a sequential nonce occurs after 2^64 encryptions, which is not a concern for our use cases.
// Even if that occurs, the nonce counter would overflow and crash the process.  We have no concerns
// around plaintext length because all stored items are small (less than 2 MB).  To prevent the
// chance of the block cipher being accidentally re-used, it is not taken in as input.  Instead,
// a new random key is generated and returned on every invocation of this function.  This key is
// used as the input to the block cipher.  If the key is stored and retrieved at a later point,
// it can be passed to NewGCMTransformer(aes.NewCipher(key)) to construct a transformer capable
// of decrypting values encrypted by this transformer (that transformer must not be used for encryption).
func NewGCMTransformerWithUniqueKeyUnsafe() (value.Transformer, []byte, error) {
	key, err := generateKey(commonSize)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	nonceGen := &nonceGenerator{
		// we start the nonce counter at one billion so that we are
		// guaranteed to detect rollover across different go routines
		zero:  1_000_000_000,
		fatal: die,
	}
	nonceGen.nonce.Add(nonceGen.zero)

	transformer, err := newGCMTransformerWithUniqueKeyUnsafe(block, nonceGen)
	if err != nil {
		return nil, nil, err
	}
	return transformer, key, nil
}

func newGCMTransformerWithUniqueKeyUnsafe(block cipher.Block, nonceGen *nonceGenerator) (*gcm, error) {
	aead, err := newGCM(block)
	if err != nil {
		return nil, err
	}

	nonceFunc := func(b []byte) error {
		// we only need 8 bytes to store our 64 bit incrementing nonce
		// instead of leaving the unused bytes as zeros, set those to random bits
		// this mostly protects us from weird edge cases like a VM restore that rewinds our atomic counter
		randNonceSize := len(b) - 8

		if err := randomNonce(b[:randNonceSize]); err != nil {
			return err
		}

		nonceGen.next(b[randNonceSize:])

		return nil
	}

	return &gcm{aead: aead, nonceFunc: nonceFunc}, nil
}

func newGCM(block cipher.Block) (cipher.AEAD, error) {
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if nonceSize := aead.NonceSize(); nonceSize != 12 { // all data in etcd will be broken if this ever changes
		return nil, fmt.Errorf("crypto/cipher.NewGCM returned unexpected nonce size: %d", nonceSize)
	}
	return aead, nil
}

func randomNonce(b []byte) error {
	_, err := rand.Read(b)
	return err
}

type nonceGenerator struct {
	// even at one million encryptions per second, this counter is enough for half a million years
	// using this struct avoids alignment bugs: https://pkg.go.dev/sync/atomic#pkg-note-BUG
	nonce atomic.Uint64
	zero  uint64
	fatal func(msg string)
}

func (n *nonceGenerator) next(b []byte) {
	incrementingNonce := n.nonce.Add(1)
	if incrementingNonce <= n.zero {
		// this should never happen, and is unrecoverable if it does
		n.fatal("aes-gcm detected nonce overflow - cryptographic wear out has occurred")
	}
	binary.LittleEndian.PutUint64(b, incrementingNonce)
}

func die(msg string) {
	// nolint:logcheck // we want the stack traces, log flushing, and process exiting logic from FatalDepth
	klog.FatalDepth(1, msg)
}

// generateKey generates a random key using system randomness.
func generateKey(length int) (key []byte, err error) {
	defer func(start time.Time) {
		value.RecordDataKeyGeneration(start, err)
	}(time.Now())
	key = make([]byte, length)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

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
	if seedLen := len(seed); seedLen < commonSize {
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
	seed, err := generateKey(commonSize)
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
	if len(data) < commonSize {
		return nil, false, errors.New("the stored data was shorter than the required size")
	}

	info := data[:commonSize]

	transformer, err := e.derivedKeyTransformer(info, dataCtx, false)
	if err != nil {
		return nil, false, fmt.Errorf("failed to derive read key from KDF: %w", err)
	}

	return transformer.TransformFromStorage(ctx, data, dataCtx)
}

func (e *extendedNonceGCM) TransformToStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, error) {
	info := make([]byte, commonSize)
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
		info = deepCopySlice(info)
	}

	key, err := e.sha256KDFExpandOnly(info)
	if err != nil {
		return nil, fmt.Errorf("failed to KDF expand seed with info: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to build cipher with KDF derived key: %w", err)
	}

	transformer, err := newGCMTransformerWithInfo(block, info)
	if err != nil {
		return nil, fmt.Errorf("failed to build transformer with KDF derived key: %w", err)
	}

	e.cache.set(dataCtx, transformer)

	return transformer, nil
}

func (e *extendedNonceGCM) sha256KDFExpandOnly(info []byte) ([]byte, error) {
	kdf := hkdf.Expand(sha256.New, e.seed, info)

	derivedKey := make([]byte, commonSize)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to read a derived key from KDF: %w", err)
	}

	return derivedKey, nil
}

func deepCopySlice(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func (t *gcm) TransformFromStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, bool, error) {
	nonceSize := t.aead.NonceSize()
	infoLen := len(t.info)
	if len(data) < infoLen+nonceSize {
		return nil, false, errors.New("the stored data was shorter than the required size")
	}
	result, err := t.aead.Open(nil, data[infoLen:infoLen+nonceSize], data[infoLen+nonceSize:], dataCtx.AuthenticatedData())
	return result, false, err
}

func (t *gcm) TransformToStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, error) {
	nonceSize := t.aead.NonceSize()
	infoLen := len(t.info)
	result := make([]byte, infoLen+nonceSize+t.aead.Overhead()+len(data))

	copy(result, t.info)

	if err := t.nonceFunc(result[infoLen : infoLen+nonceSize]); err != nil {
		return nil, fmt.Errorf("failed to write nonce for AES-GCM: %w", err)
	}

	cipherText := t.aead.Seal(result[infoLen+nonceSize:infoLen+nonceSize], result[infoLen:infoLen+nonceSize], data, dataCtx.AuthenticatedData())
	return result[:infoLen+nonceSize+len(cipherText)], nil
}

// cbc implements encryption at rest of the provided values given a cipher.Block algorithm.
type cbc struct {
	block cipher.Block
}

// NewCBCTransformer takes the given block cipher and performs encryption and decryption on the given
// data.
func NewCBCTransformer(block cipher.Block) value.Transformer {
	return &cbc{block: block}
}

var (
	errInvalidBlockSize    = errors.New("the stored data is not a multiple of the block size")
	errInvalidPKCS7Data    = errors.New("invalid PKCS7 data (empty or not padded)")
	errInvalidPKCS7Padding = errors.New("invalid padding on input")
)

func (t *cbc) TransformFromStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, bool, error) {
	blockSize := aes.BlockSize
	if len(data) < blockSize {
		return nil, false, errors.New("the stored data was shorter than the required size")
	}
	iv := data[:blockSize]
	data = data[blockSize:]

	if len(data)%blockSize != 0 {
		return nil, false, errInvalidBlockSize
	}

	result := make([]byte, len(data))
	copy(result, data)
	mode := cipher.NewCBCDecrypter(t.block, iv)
	mode.CryptBlocks(result, result)

	// remove and verify PKCS#7 padding for CBC
	c := result[len(result)-1]
	paddingSize := int(c)
	size := len(result) - paddingSize
	if paddingSize == 0 || paddingSize > len(result) {
		return nil, false, errInvalidPKCS7Data
	}
	for i := 0; i < paddingSize; i++ {
		if result[size+i] != c {
			return nil, false, errInvalidPKCS7Padding
		}
	}

	return result[:size], false, nil
}

func (t *cbc) TransformToStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, error) {
	blockSize := aes.BlockSize
	paddingSize := blockSize - (len(data) % blockSize)
	result := make([]byte, blockSize+len(data)+paddingSize)
	iv := result[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New("unable to read sufficient random bytes")
	}
	copy(result[blockSize:], data)

	// add PKCS#7 padding for CBC
	copy(result[blockSize+len(data):], bytes.Repeat([]byte{byte(paddingSize)}, paddingSize))

	mode := cipher.NewCBCEncrypter(t.block, iv)
	mode.CryptBlocks(result[blockSize:], result[blockSize:])
	return result, nil
}
