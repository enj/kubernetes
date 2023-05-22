/*
Copyright 2014 The Kubernetes Authors.

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

package serviceaccount

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	v1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	x509request "k8s.io/apiserver/pkg/authentication/request/x509"
	apiserverserviceaccount "k8s.io/apiserver/pkg/authentication/serviceaccount"
)

// ServiceAccountTokenGetter defines functions to retrieve a named service account and secret
type ServiceAccountTokenGetter interface {
	GetServiceAccount(namespace, name string) (*v1.ServiceAccount, error)
	GetPod(namespace, name string) (*v1.Pod, error)
	GetSecret(namespace, name string) (*v1.Secret, error)
}

type TokenGenerator interface {
	// GenerateToken generates a token which will identify the given
	// ServiceAccount. privateClaims is an interface that will be
	// serialized into the JWT payload JSON encoding at the root level of
	// the payload object. Public claims take precedent over private
	// claims i.e. if both claims and privateClaims have an "exp" field,
	// the value in claims will be used.
	GenerateToken(claims *jwt.Claims, privateClaims interface{}) (string, error)
}

// JWTTokenGenerator returns a TokenGenerator that generates signed JWT tokens, using the given privateKey.
// privateKey is a PEM-encoded byte array of a private RSA key.
func JWTTokenGenerator(iss string, privateKey interface{}, certs []*x509.Certificate) (TokenGenerator, error) {
	var signer jose.Signer
	var opts *jose.SignerOptions
	var err error

	if len(certs) > 0 {
		x5c := make([]string, 0, len(certs))
		for _, cert := range certs {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		opts = (&jose.SignerOptions{}).WithHeader("x5c", x5c)
	}

	switch pk := privateKey.(type) {
	case *rsa.PrivateKey:
		signer, err = signerFromRSAPrivateKey(pk, opts)
		if err != nil {
			return nil, fmt.Errorf("could not generate signer for RSA keypair: %v", err)
		}
	case *ecdsa.PrivateKey:
		signer, err = signerFromECDSAPrivateKey(pk, opts)
		if err != nil {
			return nil, fmt.Errorf("could not generate signer for ECDSA keypair: %v", err)
		}
	case jose.OpaqueSigner:
		signer, err = signerFromOpaqueSigner(pk, opts)
		if err != nil {
			return nil, fmt.Errorf("could not generate signer for OpaqueSigner: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown private key type %T, must be *rsa.PrivateKey, *ecdsa.PrivateKey, or jose.OpaqueSigner", privateKey)
	}

	return &jwtTokenGenerator{
		iss:    iss,
		signer: signer,
	}, nil
}

// keyIDFromPublicKey derives a key ID non-reversibly from a public key.
//
// The Key ID is field on a given on JWTs and JWKs that help relying parties
// pick the correct key for verification when the identity party advertises
// multiple keys.
//
// Making the derivation non-reversible makes it impossible for someone to
// accidentally obtain the real key from the key ID and use it for token
// validation.
func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

func signerFromRSAPrivateKey(keyPair *rsa.PrivateKey, opts *jose.SignerOptions) (jose.Signer, error) {
	keyID, err := keyIDFromPublicKey(&keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keyID: %v", err)
	}

	// IMPORTANT: If this function is updated to support additional key sizes,
	// algorithmForPublicKey in serviceaccount/openidmetadata.go must also be
	// updated to support the same key sizes. Today we only support RS256.

	// Wrap the RSA keypair in a JOSE JWK with the designated key ID.
	privateJWK := &jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       keyPair,
		KeyID:     keyID,
		Use:       "sig",
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       privateJWK,
		},
		opts,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	return signer, nil
}

func signerFromECDSAPrivateKey(keyPair *ecdsa.PrivateKey, opts *jose.SignerOptions) (jose.Signer, error) {
	var alg jose.SignatureAlgorithm
	switch keyPair.Curve {
	case elliptic.P256():
		alg = jose.ES256
	case elliptic.P384():
		alg = jose.ES384
	case elliptic.P521():
		alg = jose.ES512
	default:
		return nil, fmt.Errorf("unknown private key curve, must be 256, 384, or 521")
	}

	keyID, err := keyIDFromPublicKey(&keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keyID: %v", err)
	}

	// Wrap the ECDSA keypair in a JOSE JWK with the designated key ID.
	privateJWK := &jose.JSONWebKey{
		Algorithm: string(alg),
		Key:       keyPair,
		KeyID:     keyID,
		Use:       "sig",
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key:       privateJWK,
		},
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	return signer, nil
}

func signerFromOpaqueSigner(opaqueSigner jose.OpaqueSigner, opts *jose.SignerOptions) (jose.Signer, error) {
	alg := jose.SignatureAlgorithm(opaqueSigner.Public().Algorithm)

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: &jose.JSONWebKey{
				Algorithm: string(alg),
				Key:       opaqueSigner,
				KeyID:     opaqueSigner.Public().KeyID,
				Use:       "sig",
			},
		},
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	return signer, nil
}

type jwtTokenGenerator struct {
	iss    string
	signer jose.Signer
}

func (j *jwtTokenGenerator) GenerateToken(claims *jwt.Claims, privateClaims interface{}) (string, error) {
	// claims are applied in reverse precedence
	return jwt.Signed(j.signer).
		Claims(privateClaims).
		Claims(claims).
		Claims(&jwt.Claims{
			Issuer: j.iss,
		}).
		CompactSerialize()
}

// JWTTokenAuthenticator authenticates tokens as JWT tokens produced by JWTTokenGenerator
// Token signatures are verified using each of the given public keys until one works (allowing key rotation)
// If lookup is true, the service account and secret referenced as claims inside the token are retrieved and verified with the provided ServiceAccountTokenGetter
func JWTTokenAuthenticator(issuers []string, keys []interface{}, implicitAuds authenticator.Audiences, validator Validator, verifyOptionsFn x509request.VerifyOptionFunc) authenticator.Token {
	issuersMap := make(map[string]bool)
	for _, issuer := range issuers {
		issuersMap[issuer] = true
	}
	return &jwtTokenAuthenticator{
		issuers:      issuersMap,
		keys:         keys,
		implicitAuds: implicitAuds,
		validator:    validator,
		verifyOptionsFn: func() (x509.VerifyOptions, bool) {
			if verifyOptionsFn == nil {
				return x509.VerifyOptions{}, false
			}

			opts, ok := verifyOptionsFn()
			if !ok {
				return x509.VerifyOptions{}, false
			}

			// intermediates must be nil to allow the token to provide them
			opts.Intermediates = nil

			// TODO update logic to check all issuers and explicitly ignore wildcard DNS names
			//   actually *ONLY* the iss claim should be valid - fine to rely on it after hasCorrectIssuer
			opts.DNSName = "no-wildcard.<base32/64 sha256 hash of issuers[0]>.certsign.serviceaccount.authentication.k8s.io"

			// TODO should other usages be considered valid?
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

			return opts, true
		},
	}
}

type jwtTokenAuthenticator struct {
	issuers         map[string]bool
	keys            []interface{}
	validator       Validator
	implicitAuds    authenticator.Audiences
	verifyOptionsFn x509request.VerifyOptionFunc
}

// Validator is called by the JWT token authenticator to apply domain specific
// validation to a token and extract user information.
type Validator interface {
	// Validate validates a token and returns user information or an error.
	// Validator can assume that the issuer and signature of a token are already
	// verified when this function is called.
	Validate(ctx context.Context, tokenData string, public *jwt.Claims, private interface{}) (*apiserverserviceaccount.ServiceAccountInfo, error)
	// NewPrivateClaims returns a struct that the authenticator should
	// deserialize the JWT payload into. The authenticator may then pass this
	// struct back to the Validator as the 'private' argument to a Validate()
	// call. This struct should contain fields for any private claims that the
	// Validator requires to validate the JWT.
	NewPrivateClaims() interface{}
}

func (j *jwtTokenAuthenticator) AuthenticateToken(ctx context.Context, tokenData string) (*authenticator.Response, bool, error) {
	if !j.hasCorrectIssuer(tokenData) {
		return nil, false, nil
	}

	tok, err := jwt.ParseSigned(tokenData)
	if err != nil {
		return nil, false, nil
	}

	public := &jwt.Claims{}
	private := j.validator.NewPrivateClaims()

	// TODO: Pick the key that has the same key ID as `tok`, if one exists.
	var (
		found   bool
		errlist []error
	)
	for _, key := range j.keys {
		if err := tok.Claims(key, public, private); err != nil {
			errlist = append(errlist, err)
			continue
		}
		found = true
		break
	}

	if !found {
		if opts, ok := j.verifyOptionsFn(); ok && hasCertificateBasedSingleSignature(tok) {
			if err := validateTokenViaCertificateSigning(tokenData, opts, tok, public, private); err != nil {
				errlist = append(errlist, err)
			} else {
				found = true
			}
		}
	}

	if !found {
		return nil, false, utilerrors.NewAggregate(errlist)
	}

	tokenAudiences := authenticator.Audiences(public.Audience)
	if len(tokenAudiences) == 0 {
		// only apiserver audiences are allowed for legacy tokens
		audit.AddAuditAnnotation(ctx, "authentication.k8s.io/legacy-token", public.Subject)
		legacyTokensTotal.WithContext(ctx).Inc()
		tokenAudiences = j.implicitAuds
	}

	requestedAudiences, ok := authenticator.AudiencesFrom(ctx)
	if !ok {
		// default to apiserver audiences
		requestedAudiences = j.implicitAuds
	}

	auds := authenticator.Audiences(tokenAudiences).Intersect(requestedAudiences)
	if len(auds) == 0 && len(j.implicitAuds) != 0 {
		return nil, false, fmt.Errorf("token audiences %q is invalid for the target audiences %q", tokenAudiences, requestedAudiences)
	}

	// If we get here, we have a token with a recognized signature and
	// issuer string.
	sa, err := j.validator.Validate(ctx, tokenData, public, private)
	if err != nil {
		return nil, false, err
	}

	return &authenticator.Response{
		User:      sa.UserInfo(),
		Audiences: auds,
	}, true, nil
}

// hasCorrectIssuer returns true if tokenData is a valid JWT in compact
// serialization format and the "iss" claim matches the iss field of this token
// authenticator, and otherwise returns false.
//
// Note: go-jose currently does not allow access to unverified JWS payloads.
// See https://github.com/square/go-jose/issues/169
func (j *jwtTokenAuthenticator) hasCorrectIssuer(tokenData string) bool {
	parts := strings.Split(tokenData, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	claims := struct {
		// WARNING: this JWT is not verified. Do not trust these claims.
		Issuer string `json:"iss"`
	}{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	return j.issuers[claims.Issuer]
}

func validateTokenViaCertificateSigning(tokenData string, opts x509.VerifyOptions, tok *jwt.JSONWebToken, public *jwt.Claims, private interface{}) error {
	// we end up double parsing the token data because the JWT struct does not expose the Protected header of the JWS struct
	sig, err := jose.ParseSigned(tokenData)
	if err != nil {
		return err
	}

	// this should never happen because we validate the header length in hasCertificateBasedSingleSignature
	if sigs := len(sig.Signatures); sigs != 1 {
		return fmt.Errorf("only a single signature is supported for certificate based signing, got %d", sigs)
	}

	chains, err := sig.Signatures[0].Protected.Certificates(opts)
	if err != nil {
		return err
	}

	// TODO confirm that at least one chain in still valid based on revocation CRL URL from roots

	leaf := chains[0][0] // all chains have the same first element (the leaf that chains up to some cert in opts.Roots)

	// TODO not sure if we need this check
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("leaf certificate used to sign token must include digital signature key usage")
	}

	return tok.Claims(leaf.PublicKey, public, private)
}

func hasCertificateBasedSingleSignature(tok *jwt.JSONWebToken) bool {
	if len(tok.Headers) != 1 {
		return false // only support a single signature just like JSONWebSignature.Verify
	}

	// TODO: this is a hack to get around the x5c header not being easily observable,
	//  but it could be expensive so we need to have a more direct way
	_, err := tok.Headers[0].Certificates(x509.VerifyOptions{})
	return err == nil || err.Error() != "square/go-jose: no x5c header present in message"
}
