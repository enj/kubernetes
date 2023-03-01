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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"k8s.io/apiserver/pkg/storage/value"
)

// gcm implements AEAD encryption of the provided values given a cipher.Block algorithm.
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
type gcm struct {
	block cipher.Block
	nonce atomic.Uint64
}

// NewGCMTransformer takes the given block cipher and performs encryption and decryption on the given
// data.
func NewGCMTransformer(block cipher.Block) value.Transformer {
	return &gcm{block: block}
}

func (t *gcm) TransformFromStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, bool, error) {
	aead, err := cipher.NewGCM(t.block)
	if err != nil {
		return nil, false, err
	}
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, false, fmt.Errorf("the stored data was shorter than the required size")
	}
	result, err := aead.Open(nil, data[:nonceSize], data[nonceSize:], dataCtx.AuthenticatedData())
	return result, false, err
}

func (t *gcm) TransformToStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, error) { // TODO unit test changes
	aead, err := cipher.NewGCM(t.block)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	result := make([]byte, nonceSize+aead.Overhead()+len(data))

	// we only need 8 bytes to store our 64 bit incrementing nonce
	// instead of leaving the unused bytes as zeros, set those to random bits
	// this mostly protects us from weird edge cases like a VM restore that rewinds our atomic counter
	randNonceSize := nonceSize - 8

	n, err := rand.Read(result[:randNonceSize])
	if err != nil {
		return nil, err
	}
	if n != randNonceSize {
		return nil, fmt.Errorf("unable to read sufficient random bytes")
	}

	incrementingNonce := t.nonce.Add(1)
	if incrementingNonce == 0 {
		panic("aes-gcm detected nonce overflow") // this should never happen, and is unrecoverable if it does
	}
	binary.LittleEndian.PutUint64(result[randNonceSize:nonceSize], incrementingNonce)

	cipherText := aead.Seal(result[nonceSize:nonceSize], result[:nonceSize], data, dataCtx.AuthenticatedData())
	return result[:nonceSize+len(cipherText)], nil
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
	ErrInvalidBlockSize    = fmt.Errorf("the stored data is not a multiple of the block size")
	errInvalidPKCS7Data    = errors.New("invalid PKCS7 data (empty or not padded)")
	errInvalidPKCS7Padding = errors.New("invalid padding on input")
)

func (t *cbc) TransformFromStorage(ctx context.Context, data []byte, dataCtx value.Context) ([]byte, bool, error) {
	blockSize := aes.BlockSize
	if len(data) < blockSize {
		return nil, false, fmt.Errorf("the stored data was shorter than the required size")
	}
	iv := data[:blockSize]
	data = data[blockSize:]

	if len(data)%blockSize != 0 {
		return nil, false, ErrInvalidBlockSize
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
		return nil, fmt.Errorf("unable to read sufficient random bytes")
	}
	copy(result[blockSize:], data)

	// add PKCS#7 padding for CBC
	copy(result[blockSize+len(data):], bytes.Repeat([]byte{byte(paddingSize)}, paddingSize))

	mode := cipher.NewCBCEncrypter(t.block, iv)
	mode.CryptBlocks(result[blockSize:], result[blockSize:])
	return result, nil
}
