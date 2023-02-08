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

package encryption

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/kms/service"
)

const (
	referenceSuffix = ".reference.encryption.k8s.io"
	// referenceKEKAnnotationKey is the key used to store the localKEK in the annotations.
	referenceKEKAnnotationKey               = "encrypted-kek" + referenceSuffix
	referenceAuthenticatedDataAnnotationKey = "authenticated-data" + referenceSuffix
	numAnnotations                          = 2
)

// LocalKEKService adds an additional KEK layer to reduce calls to the remote
// KMS.
// The KEKs are stored as transformers in the local store. The encrypted
// form of the KEK is used to pick a transformer from the store. The KEKs should
// be encrypted by the remote KMS.
// There is a distinguished KEK (localKEK), that is generated and used by the
// LocalKEKService to encrypt.
type LocalKEKService struct {
	// remoteKMS is the remote kms that is used to encrypt the local KEKs.
	remoteKMS  service.Service
	remoteOnce sync.Once

	// transformers is a store that holds all known transformers.
	transformers TransformerCache
	// createTransformer creates a new transformer and appropriate keys.
	createTransformer CreateTransformer

	remoteKMSResponse   *service.EncryptResponse
	localTransformer    Transformer
	localTransformerErr error
}

// NewLocalKEKService is being initialized with a key that is encrypted by the
// remoteService. In the current implementation, the localKEK Service needs to be
// restarted by the caller after security thresholds are met.
func NewLocalKEKService(
	remoteService service.Service,
	store TransformerCache,
	createTransformer CreateTransformer,
) *LocalKEKService {
	return &LocalKEKService{
		remoteKMS: remoteService,

		transformers:      store,
		createTransformer: createTransformer,
	}
}

func (m *LocalKEKService) getTransformerForEncryption(uid string) (Transformer, *service.EncryptResponse, error) {
	// It could happen that the localKEK is not available, if the store is an expiring cache.
	// 1. Check if we have a local KEK
	//   - If exists, use the local KEK for encryption and return
	//   - Not exists, generate local KEK, encrypt with remote KEK ,store it in cache encrypt the data and return (this can be expensive but only 1 in N calls will incur this additional latency, N being number of times local KEK is reused)
	m.remoteOnce.Do(func() {
		m.localTransformerErr = wait.PollImmediateWithContext(context.Background(), time.Second, 5*time.Minute,
			func(ctx context.Context) (done bool, err error) {
				key, err := m.createTransformer.Key()
				if err != nil {
					return false, fmt.Errorf("failed to create local KEK: %w", err)
				}
				transformer, err := m.createTransformer.Transformer(ctx, key)
				if err != nil {
					return false, fmt.Errorf("failed to create transformer: %w", err)
				}
				resp, err := m.remoteKMS.Encrypt(ctx, uid, key)
				if err != nil {
					klog.ErrorS(err, "failed to encrypt local KEK with remote KMS", "uid", uid)
					return false, nil
				}
				if err = validateRemoteKMSResponse(resp); err != nil {
					return false, fmt.Errorf("response annotations failed validation: %w", err)
				}
				m.remoteKMSResponse = copyResponseAndAddLocalKEKAnnotation(resp)
				m.localTransformer = transformer
				m.transformers.Add(resp.Ciphertext, transformer)
				return true, nil
			})
	})
	return m.localTransformer, m.remoteKMSResponse, m.localTransformerErr
}

func copyResponseAndAddLocalKEKAnnotation(resp *service.EncryptResponse) *service.EncryptResponse {
	annotations := make(map[string][]byte, len(resp.Annotations)+numAnnotations-1)
	for s, bytes := range resp.Annotations {
		s := s
		bytes := bytes
		annotations[s] = bytes
	}
	annotations[referenceKEKAnnotationKey] = resp.Ciphertext

	return &service.EncryptResponse{
		KeyID:       resp.KeyID,
		Annotations: annotations,
	}
}

// Encrypt encrypts the plaintext with the localKEK.
func (m *LocalKEKService) Encrypt(ctx context.Context, uid string, pt []byte) (*service.EncryptResponse, error) {
	transformer, resp, err := m.getTransformerForEncryption(uid)
	if err != nil {
		klog.V(2).InfoS("encrypt plaintext", "id", uid, "err", err)
		return nil, err
	}

	authenticatedData, err := generateAuthenticatedData(32)
	if err != nil {
		return nil, err
	}

	ct, err := transformer.TransformToStorage(ctx, pt, DefaultContext(authenticatedData))
	if err != nil {
		klog.V(2).InfoS("encrypt plaintext", "id", uid, "err", err)
		return nil, err
	}

	return &service.EncryptResponse{
		Ciphertext:  ct,
		KeyID:       resp.KeyID, // TODO what about rotation ??
		Annotations: addAuthenticatedDataToAnnotations(resp.Annotations, authenticatedData),
	}, nil
}

func generateAuthenticatedData(length int) (key []byte, err error) {
	key = make([]byte, length)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func addAuthenticatedDataToAnnotations(annotations map[string][]byte, data []byte) map[string][]byte {
	annotationsOut := make(map[string][]byte, len(annotations)+1)
	for s, bytes := range annotations {
		s := s
		bytes := bytes
		annotationsOut[s] = bytes
	}
	annotationsOut[referenceAuthenticatedDataAnnotationKey] = data
	return annotationsOut
}

func (m *LocalKEKService) getTransformerForDecryption(ctx context.Context, uid string, req *service.DecryptRequest) (Transformer, error) {
	encKEK := req.Annotations[referenceKEKAnnotationKey]

	transformer, ok := m.transformers.Get(encKEK)
	if ok {
		return transformer, nil
	}

	key, err := m.remoteKMS.Decrypt(ctx, uid, &service.DecryptRequest{
		Ciphertext:  encKEK,
		KeyID:       req.KeyID,
		Annotations: annotationsWithoutReferenceKeys(req.Annotations),
	})
	if err != nil {
		return nil, err
	}

	transformer, err = m.createTransformer.Transformer(ctx, key)
	if err != nil {
		return nil, err
	}

	// Overwrite the plain key with 0s.
	copy(key, make([]byte, len(key)))

	m.transformers.Add(encKEK, transformer)

	return transformer, nil
}

// Decrypt attempts to decrypt the ciphertext with the localKEK, a KEK from the
// store, or the remote KMS.
func (m *LocalKEKService) Decrypt(ctx context.Context, uid string, req *service.DecryptRequest) ([]byte, error) {
	if _, ok := req.Annotations[referenceKEKAnnotationKey]; !ok {
		return nil, fmt.Errorf("unable to find local KEK for request with uid %q", uid)
	}
	if _, ok := req.Annotations[referenceAuthenticatedDataAnnotationKey]; !ok {
		return nil, fmt.Errorf("unable to find authenticated data for request with uid %q", uid)
	}

	transformer, err := m.getTransformerForDecryption(ctx, uid, req)
	if err != nil {
		klog.V(2).InfoS("decrypt ciphertext", "id", uid, "err", err)
		return nil, fmt.Errorf("failed to get transformer for decryption: %w", err)
	}

	pt, _, err := transformer.TransformFromStorage(ctx, req.Ciphertext, DefaultContext(req.Annotations[referenceAuthenticatedDataAnnotationKey]))
	if err != nil {
		klog.V(2).InfoS("decrypt ciphertext with pulled key", "id", uid, "err", err)
		return nil, err
	}

	return pt, nil
}

func annotationsWithoutReferenceKeys(annotations map[string][]byte) map[string][]byte {
	if len(annotations) == numAnnotations {
		return nil
	}

	m := make(map[string][]byte, len(annotations)-numAnnotations)
	for k, v := range annotations {
		if strings.HasSuffix(k, referenceSuffix) {
			continue
		}
		m[k] = v
	}
	return m
}

func validateRemoteKMSResponse(resp *service.EncryptResponse) error {
	// validate annotations don't contain the reference implementation annotations
	for k := range resp.Annotations {
		if strings.HasSuffix(k, referenceSuffix) {
			return fmt.Errorf("annotation keys are not allowed to use k8s.io or kubernetes.io")
		}
	}
	return nil
}
