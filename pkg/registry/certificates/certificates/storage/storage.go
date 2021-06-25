/*
Copyright 2016 The Kubernetes Authors.

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

package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/util/dryrun"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	"k8s.io/kubernetes/pkg/apis/certificates"
	"k8s.io/kubernetes/pkg/printers"
	printersinternal "k8s.io/kubernetes/pkg/printers/internalversion"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"
	csrregistry "k8s.io/kubernetes/pkg/registry/certificates/certificates"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
)

// REST implements a RESTStorage for CertificateSigningRequest.
type REST struct {
	*genericregistry.Store
}

// NewREST returns a registry which will store CertificateSigningRequest in the given helper.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, *StatusREST, *ApprovalREST, error) {
	store := &genericregistry.Store{
		NewFunc:                  func() runtime.Object { return &certificates.CertificateSigningRequest{} },
		NewListFunc:              func() runtime.Object { return &certificates.CertificateSigningRequestList{} },
		DefaultQualifiedResource: certificates.Resource("certificatesigningrequests"),

		CreateStrategy:      csrregistry.Strategy,
		UpdateStrategy:      csrregistry.Strategy,
		DeleteStrategy:      csrregistry.Strategy,
		ResetFieldsStrategy: csrregistry.Strategy,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: csrregistry.GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, nil, nil, err
	}

	// Subresources use the same store and creation strategy, which only
	// allows empty subs. Updates to an existing subresource are handled by
	// dedicated strategies.
	statusStore := *store
	statusStore.UpdateStrategy = csrregistry.StatusStrategy
	statusStore.ResetFieldsStrategy = csrregistry.StatusStrategy
	statusStore.BeginUpdate = countCSRDurationMetric(csrDurationRequested, csrDurationHonored)

	approvalStore := *store
	approvalStore.UpdateStrategy = csrregistry.ApprovalStrategy
	approvalStore.ResetFieldsStrategy = csrregistry.ApprovalStrategy

	return &REST{store}, &StatusREST{store: &statusStore}, &ApprovalREST{store: &approvalStore}, nil
}

// Implement ShortNamesProvider
var _ rest.ShortNamesProvider = &REST{}

// ShortNames implements the ShortNamesProvider interface. Returns a list of short names for a resource.
func (r *REST) ShortNames() []string {
	return []string{"csr"}
}

// StatusREST implements the REST endpoint for changing the status of a CSR.
type StatusREST struct {
	store *genericregistry.Store
}

// New creates a new CertificateSigningRequest object.
func (r *StatusREST) New() runtime.Object {
	return &certificates.CertificateSigningRequest{}
}

// Get retrieves the object from the storage. It is required to support Patch.
func (r *StatusREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters the status subset of an object.
func (r *StatusREST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	// We are explicitly setting forceAllowCreate to false in the call to the underlying storage because
	// subresources should never allow create on update.
	return r.store.Update(ctx, name, objInfo, createValidation, updateValidation, false, options)
}

// GetResetFields implements rest.ResetFieldsStrategy
func (r *StatusREST) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	return r.store.GetResetFields()
}

var _ = rest.Patcher(&StatusREST{})

// ApprovalREST implements the REST endpoint for changing the approval state of a CSR.
type ApprovalREST struct {
	store *genericregistry.Store
}

// New creates a new CertificateSigningRequest object.
func (r *ApprovalREST) New() runtime.Object {
	return &certificates.CertificateSigningRequest{}
}

// Get retrieves the object from the storage. It is required to support Patch.
func (r *ApprovalREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters the approval subset of an object.
func (r *ApprovalREST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	// We are explicitly setting forceAllowCreate to false in the call to the underlying storage because
	// subresources should never allow create on update.
	return r.store.Update(ctx, name, objInfo, createValidation, updateValidation, false, options)
}

// GetResetFields implements rest.ResetFieldsStrategy
func (r *ApprovalREST) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	return r.store.GetResetFields()
}

var _ = rest.Patcher(&ApprovalREST{})

func countCSRDurationMetric(requested, honored counterVecMetric) genericregistry.BeginUpdateFunc {
	return func(ctx context.Context, obj runtime.Object, old runtime.Object, options *metav1.UpdateOptions) (genericregistry.FinishFunc, error) {
		return func(ctx context.Context, success bool) {
			if !success {
				return
			}

			if dryrun.IsDryRun(options.DryRun) {
				return
			}

			if !utilfeature.DefaultFeatureGate.Enabled(features.CSRDuration) {
				return
			}

			newCSR := obj.(*certificates.CertificateSigningRequest)
			oldCSR := old.(*certificates.CertificateSigningRequest)

			if len(oldCSR.Status.Certificate) > 0 {
				return
			}

			if len(newCSR.Status.Certificate) == 0 {
				return
			}

			if oldCSR.Spec.ExpirationSeconds == nil {
				return
			}

			// TODO add comments
			// TODO add unit tests

			signer := compressSignerName(oldCSR.Spec.SignerName)

			requested.WithLabelValues(signer).Inc()

			certs, err := cert.ParseCertsPEM(newCSR.Status.Certificate)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("metrics recording failed to parse certificate for CSR %s: %w", newCSR.Name, err))
				return
			}

			certificate := certs[0]

			wantDuration := csr.ExpirationSecondsToDuration(*oldCSR.Spec.ExpirationSeconds)

			actualDuration := certificate.NotAfter.Sub(certificate.NotBefore)

			if isDurationHonored(wantDuration, actualDuration) {
				honored.WithLabelValues(signer).Inc()
			}
		}, nil
	}
}

func isDurationHonored(want time.Duration, got time.Duration) bool {
	delta := want - got
	if delta < 0 {
		delta = -delta
	}

	// 5% of want
	// TODO should we have an upper limit on the 5%?
	maxDelta := 5*time.Minute + (want / 20)

	return delta < maxDelta
}

func compressSignerName(name string) string {
	if strings.HasPrefix(name, "kubernetes.io/") {
		return name
	}

	return "other"
}
