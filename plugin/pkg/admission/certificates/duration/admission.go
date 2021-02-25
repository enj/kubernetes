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

package duration

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

const PluginName = "CertificateStrictDuration"

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

// Validate verifies that the signer respects the durationHint field if it is specified.
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
	newCSR, ok := a.GetObject().(*api.CertificateSigningRequest)
	if !ok {
		return admission.NewForbidden(a, fmt.Errorf("expected type CertificateSigningRequest, got: %T", a.GetObject()))
	}

	// always use the oldCSR in checks below, only use newCSR via the newCSR.Status.Certificate field

	// TODO should this plugin be enabled by default in an audit only mode where it emits warnings
	//  when a CSR is created with no durationHint set and when a signer does not honor the durationHint?

	// the original requester did not specify a durationHint thus there is nothing for us to validate
	// TODO should this plugin take a parameter as config that requires the durationHint field to be set by all clients?
	if oldCSR.Spec.DurationHint == nil {
		return nil
	}

	// if the new CSR has no certificate, nothing for us to validate
	if len(newCSR.Status.Certificate) == 0 {
		return nil
	}

	// only run if the status.certificate field has been changed
	if bytes.Equal(oldCSR.Status.Certificate, newCSR.Status.Certificate) {
		return nil
	}

	certs, err := certutil.ParseCertsPEM(newCSR.Status.Certificate)
	if err != nil {
		return admission.NewForbidden(a, fmt.Errorf("failed to parse .status.certifcate for CSR %s: %w", oldCSR.Name, err))
	}

	// we only validate the first cert (the issued cert) and ignore any intermediate certs
	// TODO should this be a mutating admission plugin so that it can set a terminal CertificateFailed condition?
	end := certs[0].NotAfter
	start := certs[0].NotBefore
	if duration := end.Sub(start); duration > oldCSR.Spec.DurationHint.Duration {
		klog.V(4).InfoS("cannot sign CSR with too long duration",
			"user", a.GetUserInfo().GetName(),
			"csrName", oldCSR.Name,
			"durationHint", oldCSR.Spec.DurationHint.Duration.String(),
			"actualDuration", duration.String(),
		)
		return admission.NewForbidden(a, fmt.Errorf("user %s cannot sign CSR %s with a duration longer than %s but attempted %s",
			a.GetUserInfo().GetName(),
			oldCSR.Name,
			oldCSR.Spec.DurationHint.Duration.String(),
			duration.String(),
		))
	}

	return nil
}
