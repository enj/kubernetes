/*
Copyright 2021 The Kubernetes Authors.

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

package notafter

import (
	"bytes"
	"context"
	"fmt"
	"io"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	"k8s.io/apiserver/pkg/admission"
	api "k8s.io/kubernetes/pkg/apis/certificates"
)

const PluginName = "CertificateStrictNotAfter"

func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewPlugin(), nil
	})
}

type Plugin struct {
	*admission.Handler
}

var _ admission.ValidationInterface = &Plugin{}

func NewPlugin() *Plugin {
	return &Plugin{
		Handler: admission.NewHandler(admission.Update),
	}
}

var csrGroupResource = api.Resource("certificatesigningrequests")

// Validate verifies that the signer respects the notAfterHint field if it is specified.
func (p *Plugin) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	// Ignore all calls to anything other than 'certificatesigningrequests/status'.
	// Ignore all operations other than UPDATE.
	if a.GetSubresource() != "status" || a.GetResource().GroupResource() != csrGroupResource {
		return nil
	}

	oldCSR, ok := a.GetOldObject().(*api.CertificateSigningRequest)
	if !ok {
		return admission.NewForbidden(a, fmt.Errorf("expected type CertificateSigningRequest, got: %T", a.GetOldObject()))
	}
	csr, ok := a.GetObject().(*api.CertificateSigningRequest)
	if !ok {
		return admission.NewForbidden(a, fmt.Errorf("expected type CertificateSigningRequest, got: %T", a.GetObject()))
	}

	// the original requester did not specify a notAfterHint thus there is nothing for us to validate
	if oldCSR.Spec.NotAfterHint.IsZero() {
		return nil
	}

	// if the new CSR has no certificate, nothing for us to validate
	if len(csr.Status.Certificate) == 0 {
		return nil
	}

	// only run if the status.certificate field has been changed
	if bytes.Equal(oldCSR.Status.Certificate, csr.Status.Certificate) {
		return nil
	}

	certs, err := certutil.ParseCertsPEM(csr.Status.Certificate)
	if err != nil {
		return admission.NewForbidden(a, fmt.Errorf("failed to parse .status.certifcate for CSR %s: %w", csr.Name, err))
	}

	// we only validate the first cert (the issued cert) and ignore any intermediate certs
	if certs[0].NotAfter.After(oldCSR.Spec.NotAfterHint.Time) {
		klog.V(4).InfoS("cannot sign CSR with too late notAfter date",
			"user", a.GetUserInfo().GetName(),
			"csrName", oldCSR.Name,
			"notAfterHint", oldCSR.Spec.NotAfterHint.UTC().String(),
			"actualNotAfter", certs[0].NotAfter.UTC().String(),
		)
		return admission.NewForbidden(a, fmt.Errorf("user %s cannot sign CSR %s with a notAfter date later than %s but attempted %s",
			a.GetUserInfo().GetName(),
			oldCSR.Name,
			oldCSR.Spec.NotAfterHint.UTC().String(),
			certs[0].NotAfter.UTC().String(),
		))
	}

	return nil
}
