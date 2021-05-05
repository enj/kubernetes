/*
Copyright 2019 The Kubernetes Authors.

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

package authority

import (
	"crypto/x509"
	"fmt"
	"sort"
	"time"

	capi "k8s.io/api/certificates/v1"
)

// SigningPolicy validates a CertificateRequest before it's signed by the
// CertificateAuthority. It may default or otherwise mutate a certificate
// template.
type SigningPolicy interface {
	// not-exporting apply forces signing policy implementations to be internal
	// to this package.
	apply(template *x509.Certificate, usages []capi.KeyUsage, signerNotAfter time.Time) error
}

// PermissiveSigningPolicy is the signing policy historically used by the local
// signer.
//
//  * It forwards all SANs from the original signing request.
//  * It sets allowed usages as configured in the policy and based on the requested usages.
//  * It sets NotBefore based on the Backdate configured in the policy.
//  * It sets NotAfter based on the TTL and Backdate configured in the policy.
//    Short lived certificates ignore Backdate and only use TTL.
//    NotAfter is truncated to the expiration date of the signer.
//  * It zeros all extensions.
//  * It sets BasicConstraints to true.
//  * It sets IsCA to false.
//  * It validates that the signer has not expired.
type PermissiveSigningPolicy struct {
	// TTL is the certificate TTL. Now and TTL and Backdate are used to calculate the
	// NotAfter value of the certificate.  Backdate is ignored when TTL is less than Short.
	TTL time.Duration

	// Backdate and Now are used to calculate the NotBefore value of the certificate.
	Backdate time.Duration

	// Short is the duration used to determine if the lifetime of a certificate should be considered short.
	Short time.Duration

	// Now defaults to time.Now but can be stubbed for testing
	Now func() time.Time
}

func (p PermissiveSigningPolicy) apply(tmpl *x509.Certificate, usages []capi.KeyUsage, signerNotAfter time.Time) error {
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}

	ttl := p.TTL

	usage, extUsages, err := keyUsagesFromStrings(usages)
	if err != nil {
		return err
	}
	tmpl.KeyUsage = usage
	tmpl.ExtKeyUsage = extUsages
	tmpl.NotBefore = now.Add(-p.Backdate)
	tmpl.NotAfter = now.Add(ttl - p.Backdate)

	// do not backdate the end time if we consider this to be a short lived certificate
	if ttl < p.Short {
		tmpl.NotAfter = now.Add(ttl)
	}

	tmpl.ExtraExtensions = nil
	tmpl.Extensions = nil
	tmpl.BasicConstraintsValid = true
	tmpl.IsCA = false

	if !tmpl.NotBefore.Before(signerNotAfter) {
		return fmt.Errorf("the signer has expired: NotAfter=%v", signerNotAfter)
	}

	if !tmpl.NotAfter.Before(signerNotAfter) {
		tmpl.NotAfter = signerNotAfter
	}

	if !now.Before(signerNotAfter) {
		return fmt.Errorf("refusing to sign a certificate that expired in the past: NotAfter=%v", signerNotAfter)
	}

	return nil
}

var keyUsageDict = map[capi.KeyUsage]x509.KeyUsage{
	capi.UsageSigning:           x509.KeyUsageDigitalSignature,
	capi.UsageDigitalSignature:  x509.KeyUsageDigitalSignature,
	capi.UsageContentCommitment: x509.KeyUsageContentCommitment,
	capi.UsageKeyEncipherment:   x509.KeyUsageKeyEncipherment,
	capi.UsageKeyAgreement:      x509.KeyUsageKeyAgreement,
	capi.UsageDataEncipherment:  x509.KeyUsageDataEncipherment,
	capi.UsageCertSign:          x509.KeyUsageCertSign,
	capi.UsageCRLSign:           x509.KeyUsageCRLSign,
	capi.UsageEncipherOnly:      x509.KeyUsageEncipherOnly,
	capi.UsageDecipherOnly:      x509.KeyUsageDecipherOnly,
}

var extKeyUsageDict = map[capi.KeyUsage]x509.ExtKeyUsage{
	capi.UsageAny:             x509.ExtKeyUsageAny,
	capi.UsageServerAuth:      x509.ExtKeyUsageServerAuth,
	capi.UsageClientAuth:      x509.ExtKeyUsageClientAuth,
	capi.UsageCodeSigning:     x509.ExtKeyUsageCodeSigning,
	capi.UsageEmailProtection: x509.ExtKeyUsageEmailProtection,
	capi.UsageSMIME:           x509.ExtKeyUsageEmailProtection,
	capi.UsageIPsecEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
	capi.UsageIPsecTunnel:     x509.ExtKeyUsageIPSECTunnel,
	capi.UsageIPsecUser:       x509.ExtKeyUsageIPSECUser,
	capi.UsageTimestamping:    x509.ExtKeyUsageTimeStamping,
	capi.UsageOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
	capi.UsageMicrosoftSGC:    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	capi.UsageNetscapeSGC:     x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// keyUsagesFromStrings will translate a slice of usage strings from the
// certificates API ("pkg/apis/certificates".KeyUsage) to x509.KeyUsage and
// x509.ExtKeyUsage types.
func keyUsagesFromStrings(usages []capi.KeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	var keyUsage x509.KeyUsage
	var unrecognized []capi.KeyUsage
	extKeyUsages := make(map[x509.ExtKeyUsage]struct{})
	for _, usage := range usages {
		if val, ok := keyUsageDict[usage]; ok {
			keyUsage |= val
		} else if val, ok := extKeyUsageDict[usage]; ok {
			extKeyUsages[val] = struct{}{}
		} else {
			unrecognized = append(unrecognized, usage)
		}
	}

	var sorted sortedExtKeyUsage
	for eku := range extKeyUsages {
		sorted = append(sorted, eku)
	}
	sort.Sort(sorted)

	if len(unrecognized) > 0 {
		return 0, nil, fmt.Errorf("unrecognized usage values: %q", unrecognized)
	}

	return keyUsage, sorted, nil
}

type sortedExtKeyUsage []x509.ExtKeyUsage

func (s sortedExtKeyUsage) Len() int {
	return len(s)
}

func (s sortedExtKeyUsage) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortedExtKeyUsage) Less(i, j int) bool {
	return s[i] < s[j]
}
