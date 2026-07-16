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
	"net/url"
	"strings"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationapiv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission/plugin/webhook"
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
	typedadmissionregistrationv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
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
	validatingWebhookConfigurations typedadmissionregistrationv1.ValidatingWebhookConfigurationInterface
	mutatingWebhookConfigurations   typedadmissionregistrationv1.MutatingWebhookConfigurationInterface
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
		validating *admissionregistrationv1.ValidatingWebhookConfiguration
		mutating   *admissionregistrationv1.MutatingWebhookConfiguration
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
			newCtx := newContext(ctx, strings.ToLower(gvk.Kind)+"s", ref.Name, "", gvk)
			// validation guarantees the presence of this key
			admissionReviewAPIGroups := attestations[authenticationapi.AttestationAdmissionReviewAPIGroups]

			// indexing is safe to do since validation catches empty attestation values
			if err := r.authorizeAdmissionWebhookAuthnTokenRequest(newCtx, getSvcAccountUserInfo(req, ref, string(svcacct.UID)), admissionReviewAPIGroups[0]); err != nil {
				return nil, err
			}

			var err error
			switch gvk.Kind {
			case "ValidatingWebhookConfiguration":
				validating, err = getAndValidateWebhookConfig[*admissionregistrationv1.ValidatingWebhookConfiguration](newCtx, r, req, admissionReviewAPIGroups[0])
				uid = validating.UID
			case "MutatingWebhookConfiguration":
				mutating, err = getAndValidateWebhookConfig[*admissionregistrationv1.MutatingWebhookConfiguration](newCtx, r, req, admissionReviewAPIGroups[0])
				uid = mutating.UID
			}
			if err != nil {
				return nil, errors.NewForbidden(schema.GroupResource{Group: "", Resource: "serviceaccounts/token"}, svcacct.Name, fmt.Errorf("token request denied"))
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

type eitherWebhookCfg interface {
	*admissionregistrationv1.ValidatingWebhookConfiguration | *admissionregistrationv1.MutatingWebhookConfiguration
}

type eitherWebhook interface {
	admissionregistrationv1.ValidatingWebhook | admissionregistrationv1.MutatingWebhook
}

func getAndValidateWebhookConfig[T eitherWebhookCfg](newCtx context.Context, r *TokenREST, req *authenticationapi.TokenRequest, admissionReviewAPIGroups string) (T, error) {
	var t T
	switch any(t).(type) {
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		h, err := getAndValidateWebhookConfigGeneric[*admissionregistrationv1.ValidatingWebhookConfiguration, admissionregistrationv1.ValidatingWebhook](newCtx, r, req, admissionReviewAPIGroups, r.validatingWebhookConfigurations.Get)
		return any(h).(T), err
	case *admissionregistrationv1.MutatingWebhookConfiguration:
		h, err := getAndValidateWebhookConfigGeneric[*admissionregistrationv1.MutatingWebhookConfiguration, admissionregistrationv1.MutatingWebhook](newCtx, r, req, admissionReviewAPIGroups, r.mutatingWebhookConfigurations.Get)
		return any(h).(T), err
	default:
		panic("unreachable by type constraints")
	}
}

func getter[T eitherWebhookCfg, U eitherWebhook](cfg T) webhookGetter[U] {
	switch wh := any(cfg).(type) {
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		return any((*vwc)(wh)).(webhookGetter[U])
	case *admissionregistrationv1.MutatingWebhookConfiguration:
		return any((*mwc)(wh)).(webhookGetter[U])
	default:
		panic("unreachable by type constraints")
	}
}

func getAndValidateWebhookConfigGeneric[T eitherWebhookCfg, U eitherWebhook](newCtx context.Context, r *TokenREST, req *authenticationapi.TokenRequest, admissionReviewAPIGroups string, get func(context.Context, string, metav1.GetOptions) (T, error)) (T, error) {
	borName := req.Spec.BoundObjectRef.Name
	obj, err := get(newCtx, borName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	webhookGet := getter[T, U](obj)
	if err := validateWebhookAudience2(obj, webhookGet, req.Spec.Audiences[0]); err != nil {
		return nil, err
	}

	if err := validateAttestationAPIGroup2(obj, webhookGet, admissionReviewAPIGroups); err != nil {
		return nil, err
	}

	return obj, nil
}

func getSvcAccountUserInfo(req *authenticationapi.TokenRequest, ref *authenticationapi.BoundObjectReference, svcacctUID string) user.Info {
	info := serviceaccount.ServiceAccountInfo{
		Name:         req.Name,
		Namespace:    req.Namespace,
		UID:          svcacctUID,
		Attestations: req.Spec.Attestations,
	}

	return info.UserInfo()
}

type vwc admissionregistrationv1.ValidatingWebhookConfiguration
type mwc admissionregistrationv1.MutatingWebhookConfiguration
type vw admissionregistrationv1.ValidatingWebhook
type mw admissionregistrationv1.MutatingWebhook

func (v *vwc) GetWebhooks() []admissionregistrationv1.ValidatingWebhook {
	return v.Webhooks
}

func (m *mwc) GetWebhooks() []admissionregistrationv1.MutatingWebhook {
	return m.Webhooks
}

type webhookGetter[T eitherWebhook] interface {
	GetWebhooks() []T
}

func getWebhooks[T webhookGetter[U], U eitherWebhook](hook T) []U {
	return hook.GetWebhooks()
}

//	func asWebhookGetter[T eitherWebhookCfg, U eitherWebhook](cfg T) webhookGetter[U] {
//		var c any = cfg
//		switch whc := c.(type) {
//		case *admissionregistrationv1.ValidatingWebhookConfiguration:
//			return (*vwc)(whc)
//		case *admissionregistrationv1.MutatingWebhookConfiguration:
//			var t any = cfg
//			if _, ok := t.(*admissionregistrationv1.MutatingWebhookConfiguration); !ok {
//				return nil, fmt.Errorf("mismatched webhook configuration and webhook types")
//			}
//			return webhook.NewMutatingWebhookAccessor(string(a.GetUID()), a.GetName(), whc), nil
//		default:
//			panic("unreachable by type constraints")
//		}
//	}
func asAccessor[T eitherWebhookCfg, U eitherWebhook](cfg T, hook U) (webhook.WebhookAccessor, error) {
	a, err := meta.Accessor(cfg)
	if err != nil {
		return nil, err
	}

	var h any = hook
	switch wh := h.(type) {
	case *admissionregistrationv1.ValidatingWebhook:
		var t any = cfg
		if _, ok := t.(*admissionregistrationv1.ValidatingWebhookConfiguration); !ok {
			return nil, fmt.Errorf("mismatched webhook configuration and webhook types")
		}
		return webhook.NewValidatingWebhookAccessor(string(a.GetUID()), a.GetName(), wh), nil
	case *admissionregistrationv1.MutatingWebhook:
		var t any = cfg
		if _, ok := t.(*admissionregistrationv1.MutatingWebhookConfiguration); !ok {
			return nil, fmt.Errorf("mismatched webhook configuration and webhook types")
		}
		return webhook.NewMutatingWebhookAccessor(string(a.GetUID()), a.GetName(), wh), nil
	default:
		panic("unreachable by type constraints")
	}
}

// validateWebhookAudience checks that the requested audience matches at least one
// webhook's client config. For URL-configured webhooks the audience must be the URL
// verbatim. For service-configured webhooks the audience must be
// https://$name.$namespace.svc:$port[/$path].
func validateWebhookAudience2[T eitherWebhookCfg, U eitherWebhook](cfg T, gimme webhookGetter[U], audience string) error {
	hooks := gimme.GetWebhooks()
	for _, hook := range hooks {
		a, err := asAccessor(cfg, hook)
		if err != nil {
			return err
		}

		cc := a.GetClientConfig()
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
				joined, err := url.JoinPath(expected, *cc.Service.Path)
				if err != nil {
					return errors.NewInternalError(fmt.Errorf("%w: unable to validate audience", err))
				}
				expected = joined
			}
			if audience == expected {
				return nil
			}
		}

	}

	return errors.NewBadRequest("audience does not match webhook client config in the bound object")
}

// validateWebhookAudience checks that the requested audience matches at least one
// webhook's client config. For URL-configured webhooks the audience must be the URL
// verbatim. For service-configured webhooks the audience must be
// https://$name.$namespace.svc:$port[/$path].
func validateWebhookAudience(audience string, clientConfigs []admissionregistrationv1.WebhookClientConfig) error {
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
				joined, err := url.JoinPath(expected, *cc.Service.Path)
				if err != nil {
					return errors.NewInternalError(fmt.Errorf("%w: unable to validate audience", err))
				}
				expected = joined
			}
			if audience == expected {
				return nil
			}
		}
	}

	return errors.NewBadRequest("audience does not match webhook client config in the bound object")
}

// validateAttestationAPIGroup checks that the attested API group matches at least
// one Rule in the webhook configuration. A "*" attestation value skips this check
// since it represents all API groups. A "*" in a Rule's APIGroups matches any
// attested value. It is assumed that the cel expressions in the matchConditions
// properly match the AdmissionReview request for which the TokenRequest is
// being made.
func validateAttestationAPIGroup2[T eitherWebhookCfg, U eitherWebhook](cfg T, gimme webhookGetter[U], attestedGroup string) error {
	// "*" means the token is valid for all API groups; skip the check. We only
	// ever expect kube-apiserver to ever ask for this.
	if attestedGroup == "*" {
		return nil
	}

	for _, hook := range gimme.GetWebhooks() {
		a, err := asAccessor(cfg, hook)
		if err != nil {
			return err
		}

		for _, rule := range a.GetRules() {
			for _, group := range rule.APIGroups {
				// If there's an exact match
				if group == "*" || group == attestedGroup {
					return nil
				}
			}
		}
	}

	// An aggregated API Server will never need a cross-group equivalent, so we
	// do not check equivalents here.

	// If this point is reached, there are either a) no rules or b) rules but
	// none matched. If there are no rules, the invocation will never match and
	// the request should be denied.
	return fmt.Errorf("attestation does not match webhook rules")
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
