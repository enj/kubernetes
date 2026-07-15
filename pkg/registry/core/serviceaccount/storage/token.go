/*
Copyright 2018 The Kubernetes Authors.

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

	admissionregistration "k8s.io/api/admissionregistration/v1"
	authenticationapiv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	authenticationtokenjwt "k8s.io/apiserver/pkg/authentication/token/jwt"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/registry/rest"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/apiserver/pkg/warning"
	admissionregistrationv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/apis/authentication"
	authenticationapi "k8s.io/kubernetes/pkg/apis/authentication"
	authenticationvalidation "k8s.io/kubernetes/pkg/apis/authentication/validation"

	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/features"
	token "k8s.io/kubernetes/pkg/serviceaccount"
)

func (r *TokenREST) New() runtime.Object {
	return &authenticationapi.TokenRequest{}
}

// Destroy cleans up resources on shutdown.
func (r *TokenREST) Destroy() {
	// Given no underlying store, we don't destroy anything
	// here explicitly.
}

type TokenREST struct {
	svcaccts                        rest.Getter
	pods                            rest.Getter
	secrets                         rest.Getter
	nodes                           rest.Getter
	validatingWebhookConfigurations admissionregistrationv1.ValidatingWebhookConfigurationInterface
	mutatingWebhookConfigurations   admissionregistrationv1.MutatingWebhookConfigurationInterface
	authorizer                      authorizer.Authorizer
	issuer                          token.TokenGenerator
	auds                            authenticator.Audiences
	audsSet                         sets.String
	maxExpirationSeconds            int64
	extendExpiration                bool
	maxExtendedExpirationSeconds    int64
}

var _ = rest.NamedCreater(&TokenREST{})
var _ = rest.GroupVersionKindProvider(&TokenREST{})
var _ = rest.SubresourceObjectMetaPreserver(&TokenREST{})

var gvk = schema.GroupVersionKind{
	Group:   authenticationapiv1.SchemeGroupVersion.Group,
	Version: authenticationapiv1.SchemeGroupVersion.Version,
	Kind:    "TokenRequest",
}

func (r *TokenREST) Create(ctx context.Context, name string, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	req := obj.(*authenticationapi.TokenRequest)

	// Get the namespace from the context (populated from the URL).
	namespace, ok := genericapirequest.NamespaceFrom(ctx)
	if !ok {
		return nil, errors.NewBadRequest("namespace is required")
	}

	// require name/namespace in the body to match URL if specified
	if len(req.Name) > 0 && req.Name != name {
		errs := field.ErrorList{field.Invalid(field.NewPath("metadata").Child("name"), req.Name, "must match the service account name if specified")}
		return nil, errors.NewInvalid(gvk.GroupKind(), name, errs)
	}
	if len(req.Namespace) > 0 && req.Namespace != namespace {
		errs := field.ErrorList{field.Invalid(field.NewPath("metadata").Child("namespace"), req.Namespace, "must match the service account namespace if specified")}
		return nil, errors.NewInvalid(gvk.GroupKind(), name, errs)
	}

	// Lookup service account
	svcacctObj, err := r.svcaccts.Get(ctx, name, &metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	svcacct := svcacctObj.(*api.ServiceAccount)

	attestations := req.Spec.Attestations

	if len(req.UID) > 0 && req.UID != svcacct.UID {
		if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.TokenRequestServiceAccountUIDValidation) {
			return nil, errors.NewConflict(schema.GroupResource{Group: gvk.Group, Resource: gvk.Kind}, name, fmt.Errorf("the UID in the token request (%s) does not match the UID of the service account (%s)", req.UID, svcacct.UID))
		} else {
			audit.AddAuditAnnotation(ctx, "authentication.k8s.io/token-request-uid-mismatch", fmt.Sprintf("the UID in the token request (%s) does not match the UID of the service account (%s)", req.UID, svcacct.UID))
		}
	}

	// Default unset spec audiences to API server audiences based on server config
	if len(req.Spec.Audiences) == 0 {
		req.Spec.Audiences = r.auds
	}
	// Populate metadata fields if not set
	if len(req.Name) == 0 {
		req.Name = svcacct.Name
	}
	if len(req.Namespace) == 0 {
		req.Namespace = svcacct.Namespace
	}
	if len(req.UID) == 0 {
		req.UID = svcacct.UID
	} else if req.UID != svcacct.UID {
		warning.AddWarning(ctx, "", fmt.Sprintf("the UID in the token request (%s) does not match the UID of the service account (%s) but TokenRequestServiceAccountUIDValidation is not enabled. In the future, this will return a conflict error", req.UID, svcacct.UID))
	}

	// Save current time before building the token, to make sure the expiration
	// returned in TokenRequestStatus would be <= the exp field in token.
	nowTime := time.Now()
	req.CreationTimestamp = metav1.NewTime(nowTime)

	// Clear status
	req.Status = authenticationapi.TokenRequestStatus{}

	// call static validation, then validating admission
	if errs := authenticationvalidation.ValidateTokenRequest(req); len(errs) != 0 {
		return nil, errors.NewInvalid(gvk.GroupKind(), "", errs)
	}
	if createValidation != nil {
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			return nil, err
		}
	}

	var (
		pod        *api.Pod
		node       *api.Node
		secret     *api.Secret
		validating *admissionregistration.ValidatingWebhookConfiguration
		mutating   *admissionregistration.MutatingWebhookConfiguration
	)

	if ref := req.Spec.BoundObjectRef; ref != nil {
		var uid types.UID

		gvk := schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind)
		switch {
		case gvk.Group == "" && gvk.Kind == "Pod":
			newCtx := newContext(ctx, "pods", ref.Name, namespace, gvk)
			podObj, err := r.pods.Get(newCtx, ref.Name, &metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			pod = podObj.(*api.Pod)
			if name != pod.Spec.ServiceAccountName {
				return nil, errors.NewBadRequest(fmt.Sprintf("cannot bind token for serviceaccount %q to pod running with different serviceaccount name.", name))
			}
			uid = pod.UID
			if utilfeature.DefaultFeatureGate.Enabled(features.ServiceAccountTokenPodNodeInfo) {
				if nodeName := pod.Spec.NodeName; nodeName != "" {
					newCtx := newContext(ctx, "nodes", nodeName, "", api.SchemeGroupVersion.WithKind("Node"))
					// set ResourceVersion=0 to allow this to be read/served from the apiservers watch cache
					nodeObj, err := r.nodes.Get(newCtx, nodeName, &metav1.GetOptions{ResourceVersion: "0"})
					if err != nil {
						nodeObj, err = r.nodes.Get(newCtx, nodeName, &metav1.GetOptions{}) // fallback to a live lookup on any error
					}
					switch {
					case errors.IsNotFound(err):
						// if the referenced Node object does not exist, we still embed just the pod name into the
						// claims so that clients still have some indication of what node a pod is assigned to when
						// inspecting a token (even if the UID is not present).
						klog.V(4).ErrorS(err, "failed fetching node for pod", "pod", klog.KObj(pod), "podUID", pod.UID, "nodeName", nodeName)
						node = &api.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}
					case err != nil:
						return nil, errors.NewInternalError(err)
					default:
						node = nodeObj.(*api.Node)
					}
				}
			}
		case gvk.Group == "" && gvk.Kind == "Node":
			if !utilfeature.DefaultFeatureGate.Enabled(features.ServiceAccountTokenNodeBinding) {
				return nil, errors.NewBadRequest(fmt.Sprintf("cannot bind token to a Node object as the %q feature-gate is disabled", features.ServiceAccountTokenNodeBinding))
			}
			newCtx := newContext(ctx, "nodes", ref.Name, "", gvk)
			nodeObj, err := r.nodes.Get(newCtx, ref.Name, &metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			node = nodeObj.(*api.Node)
			uid = node.UID
		case gvk.Group == "" && gvk.Kind == "Secret":
			newCtx := newContext(ctx, "secrets", ref.Name, namespace, gvk)
			secretObj, err := r.secrets.Get(newCtx, ref.Name, &metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			secret = secretObj.(*api.Secret)
			uid = secret.UID
		case gvk.Group == "admissionregistration.k8s.io" && (gvk.Kind == "ValidatingWebhookConfiguration" || gvk.Kind == "MutatingWebhookConfiguration"):
			if !utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerWebhookAuthenticationToken) {
				return nil, errors.NewBadRequest(fmt.Sprintf("cannot bind token to object of type %s (feature gate %s is disabled)", gvk.String(), genericfeatures.APIServerWebhookAuthenticationToken))
			}
			newCtx := newContext(ctx, strings.ToLower(gvk.Kind), ref.Name, "", gvk)
			admissionReviewAPIGroups, ok := attestations[authenticationapi.AttestationAdmissionReviewAPIGroups]
			if !ok {
				return nil, errors.NewBadRequest(fmt.Sprintf("allowedAPIGroups attestation is required when bound object ref is of kind %s", gvk.Kind))
			}

			// indexing is safe to do since validation catches empty attestation values
			if err := r.authorizeAdmissionWebhookAuthnTokenRequest(newCtx, getSvcAccountUserInfo(req, ref), admissionReviewAPIGroups[0]); err != nil {
				return nil, err
			}

			if len(req.Spec.Audiences) != 1 {
				return nil, errors.NewBadRequest("exactly one audience is required when bound object ref is a webhook configuration")
			}

			switch gvk.Kind {
			case "ValidatingWebhookConfiguration":
				valObj, err := r.validatingWebhookConfigurations.Get(ctx, ref.Name, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				validating = valObj
				uid = validating.UID

				var clientConfigs []admissionregistration.WebhookClientConfig
				var rules []admissionregistration.RuleWithOperations
				for _, wh := range validating.Webhooks {
					clientConfigs = append(clientConfigs, wh.ClientConfig)
					rules = append(rules, wh.Rules...)
				}
				if err := validateWebhookAudience(req.Spec.Audiences[0], clientConfigs); err != nil {
					return nil, err
				}
				if ok := validateAttestationAPIGroup(admissionReviewAPIGroups[0], rules); !ok {
					return nil, errors.NewForbidden(schema.GroupResource{Group: "", Resource: "serviceaccounts/token"}, svcacct.Name, fmt.Errorf("attested API group does not match any rule in the bound webhook configuration"))
				}
			case "MutatingWebhookConfiguration":
				mutObj, err := r.mutatingWebhookConfigurations.Get(newCtx, ref.Name, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				mutating = mutObj
				uid = mutating.UID

				var clientConfigs []admissionregistration.WebhookClientConfig
				var rules []admissionregistration.RuleWithOperations
				for _, wh := range mutating.Webhooks {
					clientConfigs = append(clientConfigs, wh.ClientConfig)
					rules = append(rules, wh.Rules...)
				}
				if err := validateWebhookAudience(req.Spec.Audiences[0], clientConfigs); err != nil {
					return nil, err
				}
				if ok := validateAttestationAPIGroup(admissionReviewAPIGroups[0], rules); !ok {
					return nil, errors.NewForbidden(schema.GroupResource{Group: "", Resource: "serviceaccounts/token"}, svcacct.Name, fmt.Errorf("attested API group does not match any rule in the bound webhook configuration"))
				}
			}
		default:
			return nil, errors.NewBadRequest(fmt.Sprintf("cannot bind token to object of type %s", gvk.String()))
		}
		if ref.UID != "" && uid != ref.UID {
			return nil, errors.NewConflict(schema.GroupResource{Group: gvk.Group, Resource: gvk.Kind}, ref.Name, fmt.Errorf("the UID in the bound object reference (%s) does not match the UID in record. The object might have been deleted and then recreated", ref.UID))
		}
	}

	if r.maxExpirationSeconds > 0 && req.Spec.ExpirationSeconds > r.maxExpirationSeconds {
		// only positive value is valid
		warning.AddWarning(ctx, "", fmt.Sprintf("requested expiration of %d seconds shortened to %d seconds", req.Spec.ExpirationSeconds, r.maxExpirationSeconds))
		req.Spec.ExpirationSeconds = r.maxExpirationSeconds
	}

	// Tweak expiration for safe transition of projected service account token.
	// Warn (instead of fail) after requested expiration time.
	// Fail after hard-coded extended expiration time.
	// Only perform the extension when token is pod-bound.
	var warnAfter int64
	exp := req.Spec.ExpirationSeconds
	if r.extendExpiration && pod != nil && req.Spec.ExpirationSeconds == token.WarnOnlyBoundTokenExpirationSeconds && r.isKubeAudiences(req.Spec.Audiences) {
		warnAfter = exp
		exp = r.maxExtendedExpirationSeconds
	}

	sc, pc, err := token.Claims(*svcacct, pod, secret, node, validating, mutating, exp, warnAfter, req.Spec.Audiences, attestations)
	if err != nil {
		return nil, err
	}
	tokdata, err := r.issuer.GenerateToken(ctx, sc, pc)
	if err != nil {
		return nil, errors.NewInternalError(fmt.Errorf("failed to generate token: %v", err))
	}

	// populate status
	out := req.DeepCopy()
	out.Status = authenticationapi.TokenRequestStatus{
		Token:               tokdata,
		ExpirationTimestamp: metav1.Time{Time: nowTime.Add(time.Duration(out.Spec.ExpirationSeconds) * time.Second)},
	}
	if utilfeature.DefaultFeatureGate.Enabled(features.ServiceAccountTokenJTI) && len(sc.ID) > 0 {
		audit.AddAuditAnnotation(ctx, serviceaccount.IssuedCredentialIDAuditAnnotationKey, authenticationtokenjwt.CredentialIDForJTI(sc.ID))
	}
	return out, nil
}

func getSvcAccountUserInfo(req *authenticationapi.TokenRequest, ref *authenticationapi.BoundObjectReference) user.Info {
	info := serviceaccount.ServiceAccountInfo{
		Name:         req.Name,
		Namespace:    req.Namespace,
		UID:          string(req.UID),
		Attestations: req.Spec.Attestations,
	}

	switch ref.Kind {
	case "ValidatingWebhookConfiguration":
		info.ValidatingWebhookConfigurationName = ref.Name
		info.ValidatingWebhookConfigurationUID = string(ref.UID)
	case "MutatingWebhookConfiguration":
		info.MutatingWebhookConfigurationName = ref.Name
		info.MutatingWebhookConfigurationUID = string(ref.UID)
	}

	return info.UserInfo()
}

// validateWebhookAudience checks that the requested audience matches at least one
// webhook's client config. For URL-configured webhooks the audience must be the URL
// verbatim. For service-configured webhooks the audience must be
// https://$name.$namespace.svc:$port[/$path].
func validateWebhookAudience(audience string, clientConfigs []admissionregistration.WebhookClientConfig) error {
	for _, cc := range clientConfigs {
		if cc.URL != nil && audience == *cc.URL {
			return nil
		}
		if cc.Service != nil {
			port := int32(443)
			if cc.Service.Port != nil {
				port = *cc.Service.Port
			}
			expected := fmt.Sprintf("https://%s.%s.svc:%d", cc.Service.Name, cc.Service.Namespace, port)
			if cc.Service.Path != nil && *cc.Service.Path != "" {
				expected += *cc.Service.Path
			}
			if audience == expected {
				return nil
			}
		}
	}
	return errors.NewBadRequest(fmt.Sprintf("audience %q does not match any webhook client config in the bound object", audience))
}

// validateAttestationAPIGroup checks that the attested API group matches at least
// one Rule in the webhook configuration. A "*" attestation value skips this check
// since it represents all API groups. A "*" in a Rule's APIGroups matches any
// attested value. It is assumed that the cel expressions in the matchConditions
// properly match the AdmissionReview request for which the TokenRequest is
// being made.
func validateAttestationAPIGroup(attestedGroup string, rules []admissionregistration.RuleWithOperations) bool {
	// "*" means the token is valid for all API groups; skip the check. We only
	// ever expect kube-apiserver to ever ask for this.
	if attestedGroup == "*" {
		return true
	}

	for _, rule := range rules {
		for _, group := range rule.APIGroups {
			// If there's an exact match
			if group == "*" || group == attestedGroup {
				return true
			}
		}
	}

	// An aggregated API Server will never need a cross-group equivalent, so we
	// do not check equivalents here.

	// If this point is reached, there are either a) no rules or b) rules but
	// none matched. If there are no rules, the invocation will never match and
	// the request should be denied.
	return false
}

func (r *TokenREST) authorizeAdmissionWebhookAuthnTokenRequest(ctx context.Context, userInfo user.Info, admissionReviewAPIGroup string) error {
	attributes := authorizer.AttributesRecord{
		//TODO pass in a ServiceAccountInfo and call UserInfo() on it
		User:            userInfo,
		Verb:            "attest",
		APIVersion:      "*",
		APIGroup:        "authentication.k8s.io",
		Resource:        authentication.AttestationAdmissionReviewAPIGroups,
		ResourceRequest: true,
		Name:            admissionReviewAPIGroup,
	}

	authorized, reason, err := r.authorizer.Authorize(ctx, attributes)
	if authorized == authorizer.DecisionAllow {
		return nil
	}

	msg := reason
	switch {
	case err != nil && len(reason) > 0:
		msg = fmt.Sprintf("%v: %s", err, reason)
	case err != nil:
		msg = err.Error()
	}

	return responsewriters.ForbiddenStatusError(attributes, msg)
}

func (r *TokenREST) GroupVersionKind(schema.GroupVersion) schema.GroupVersionKind {
	return gvk
}

// newContext return a copy of ctx in which new RequestInfo is set
func newContext(ctx context.Context, resource, name, namespace string, gvk schema.GroupVersionKind) context.Context {
	newInfo := genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Verb:              "get",
		Namespace:         namespace,
		Resource:          resource,
		Name:              name,
		Parts:             []string{resource, name},
		APIGroup:          gvk.Group,
		APIVersion:        gvk.Version,
	}
	return genericapirequest.WithRequestInfo(ctx, &newInfo)
}

// isKubeAudiences returns true if the tokenaudiences is a strict subset of apiserver audiences.
func (r *TokenREST) isKubeAudiences(tokenAudience []string) bool {
	// tokenAudiences must be a strict subset of apiserver audiences
	return r.audsSet.HasAll(tokenAudience...)
}

// PreserveRequestObjectMetaSystemFieldsOnSubresourceCreate indicates that the
// TokenRequest's UID should be preserved when creating subresources
func (r *TokenREST) PreserveRequestObjectMetaSystemFieldsOnSubresourceCreate() bool {
	return true
}
