/*
Copyright 2025 The Kubernetes Authors.

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

package filters

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/cache"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server/httplog"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/apis/core/validation"
	"k8s.io/utils/lru"
)

func WithConstrainedImpersonation(handler http.Handler, a authorizer.Authorizer, s runtime.NegotiatedSerializer) http.Handler {
	tracker := newImpersonationModesTracker(a)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		wantedUser, err := processImpersonationHeaders(req.Header)
		if err != nil {
			responsewriters.InternalError(w, req, err)
			return
		}
		if wantedUser == nil {
			handler.ServeHTTP(w, req)
			return
		}
		attributes, err := GetAuthorizerAttributes(ctx)
		if err != nil {
			responsewriters.InternalError(w, req, err)
			return
		}
		requestor := attributes.GetUser()
		if requestor == nil {
			responsewriters.InternalError(w, req, errors.New("no User found in the context"))
			return
		}

		impersonatedUser, err := tracker.getImpersonatedUser(ctx, wantedUser, attributes)
		if err != nil {
			klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "err", err)
			forbidden(attributes, w, req, err, s)
			return
		}

		req = req.WithContext(request.WithUser(ctx, impersonatedUser.user))
		httplog.LogOf(req, w).Addf("%v is impersonating %v", userString(requestor), userString(impersonatedUser.user))
		audit.LogImpersonatedUser(audit.WithAuditContext(ctx), impersonatedUser.user, impersonatedUser.constraint) // TODO is impersonationConstraint part of ImpersonatedUser or a separate field in audit?

		handler.ServeHTTP(w, req)
	})
}

type impersonatedUserInfo struct {
	user       user.Info
	constraint string // the verb used in the impersonationModeUserCheck that allowed this user to be impersonated
}

type impersonationMode func(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (*impersonatedUserInfo, error)
type impersonationModeUserCheck func(ctx context.Context, wantedUser *user.DefaultInfo, requestor user.Info) (*impersonatedUserInfo, error)
type constrainedImpersonationModeFilter func(wantedUser *user.DefaultInfo, requestor user.Info) bool

func allImpersonationModes(a authorizer.Authorizer) []impersonationMode {
	return []impersonationMode{
		scheduledNodeImpersonationMode(a),
		nodeImpersonationMode(a),
		serviceAccountImpersonationMode(a),
		userInfoImpersonationMode(a),
		legacyImpersonationMode(a),
	}
}

func scheduledNodeImpersonationMode(a authorizer.Authorizer) impersonationMode {
	return buildConstrainedImpersonationMode(a, "scheduled-node",
		func(wantedUser *user.DefaultInfo, requestor user.Info) bool {
			return onlyUsernameSet(wantedUser) && requesterScheduledOnNode(requestor, wantedUser.Name)
		},
	)
}

func nodeImpersonationMode(a authorizer.Authorizer) impersonationMode {
	return buildConstrainedImpersonationMode(a, "node",
		func(wantedUser *user.DefaultInfo, _ user.Info) bool {
			if !onlyUsernameSet(wantedUser) {
				return false
			}
			_, ok := isNodeUsername(wantedUser.Name)
			return ok
		},
	)
}

func serviceAccountImpersonationMode(a authorizer.Authorizer) impersonationMode {
	return buildConstrainedImpersonationMode(a, "serviceaccount",
		func(wantedUser *user.DefaultInfo, _ user.Info) bool {
			if !onlyUsernameSet(wantedUser) {
				return false
			}
			_, _, ok := isServiceAccountUsername(wantedUser.Name)
			return ok
		},
	)
}

func userInfoImpersonationMode(a authorizer.Authorizer) impersonationMode {
	return buildConstrainedImpersonationMode(a, "user-info",
		func(wantedUser *user.DefaultInfo, _ user.Info) bool {
			// nodes and service accounts cannot be impersonated in this mode.
			// the user-info bucket is reserved for the "other" users, that is,
			// users that do not have an explicit schema defined by Kube.
			if _, ok := isNodeUsername(wantedUser.Name); ok {
				return false
			}
			if _, _, ok := isServiceAccountUsername(wantedUser.Name); ok {
				return false
			}
			return true
		},
	)
}

func legacyImpersonationMode(a authorizer.Authorizer) impersonationMode {
	check := buildImpersonationModeUserCheck(a, "impersonate", false)
	return func(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (*impersonatedUserInfo, error) {
		requestor := attributes.GetUser()
		return check(ctx, wantedUser, requestor)
	}
}

func buildConstrainedImpersonationMode(a authorizer.Authorizer, mode string, filter constrainedImpersonationModeFilter) impersonationMode {
	check := buildImpersonationModeUserCheck(a, "impersonate:"+mode, true)
	return func(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (*impersonatedUserInfo, error) {
		requestor := attributes.GetUser()
		if !filter(wantedUser, requestor) {
			return nil, nil
		}
		if err := checkAuthorization(ctx, a, &impersonateOnAttributes{mode: mode, Attributes: attributes}); err != nil {
			return nil, err
		}
		return check(ctx, wantedUser, requestor)
	}
}

func buildImpersonationModeUserCheck(a authorizer.Authorizer, verb string, isConstrainedImpersonation bool) impersonationModeUserCheck {
	usernameAndGroupGV := authenticationv1.SchemeGroupVersion
	if !isConstrainedImpersonation {
		usernameAndGroupGV = corev1.SchemeGroupVersion
	}
	// the inner cache covers the impersonation checks that are not dependent on the request info
	impCache := newImpersonationCache()
	return func(ctx context.Context, wantedUser *user.DefaultInfo, requestor user.Info) (outUser *impersonatedUserInfo, outErr error) {
		// fake attributes that just contain the requestor to allow us to reuse the cache implementation
		attributes := authorizer.AttributesRecord{User: requestor}
		if impersonatedUser := impCache.get(wantedUser, attributes); impersonatedUser != nil {
			return impersonatedUser, nil
		}
		defer func() {
			if outErr != nil || outUser == nil {
				return
			}
			impCache.set(wantedUser, attributes, outUser)
		}()

		actualUser := *wantedUser

		usernameAttributes := impersonationAttributes(requestor, usernameAndGroupGV, verb, "users", wantedUser.Name)
		// TODO node as a first class concept in impersonation is new, how strict do we want to be?
		if isConstrainedImpersonation {
			if name, ok := isNodeUsername(wantedUser.Name); ok {
				usernameAttributes.Resource = "nodes"
				usernameAttributes.Name = name

				if len(wantedUser.Groups) == 0 {
					actualUser.Groups = []string{user.NodesGroup}
				}
			}
		}
		if namespace, name, ok := isServiceAccountUsername(wantedUser.Name); ok {
			usernameAttributes.Resource = "serviceaccounts"
			usernameAttributes.Namespace = namespace
			usernameAttributes.Name = name

			if len(wantedUser.Groups) == 0 {
				// if groups aren't specified for a service account, we know the groups because it is a fixed mapping.  Add them
				actualUser.Groups = serviceaccount.MakeGroupNames(namespace)
			}
		}
		if err := checkAuthorization(ctx, a, usernameAttributes); err != nil {
			return nil, err
		}

		if len(wantedUser.UID) > 0 {
			uidAttributes := impersonationAttributes(requestor, authenticationv1.SchemeGroupVersion, verb, "uids", wantedUser.UID)
			if err := checkAuthorization(ctx, a, uidAttributes); err != nil {
				return nil, err
			}
		}

		// TODO treat system:masters differently in constrained impersonation?
		groupAttributes := impersonationAttributes(requestor, usernameAndGroupGV, verb, "groups", "")
		for _, group := range wantedUser.Groups {
			groupAttributes.Name = group
			if err := checkAuthorization(ctx, a, groupAttributes); err != nil {
				return nil, err
			}
		}

		extraAttributes := impersonationAttributes(requestor, authenticationv1.SchemeGroupVersion, verb, "userextras", "")
		for key, values := range wantedUser.Extra {
			extraAttributes.Subresource = key
			for _, value := range values {
				extraAttributes.Name = value
				if err := checkAuthorization(ctx, a, extraAttributes); err != nil {
					return nil, err
				}
			}
		}

		if actualUser.Name == user.Anonymous {
			ensureGroup(&actualUser, user.AllUnauthenticated)
		} else {
			ensureGroup(&actualUser, user.AllAuthenticated)
		}

		return &impersonatedUserInfo{user: &actualUser, constraint: verb}, nil
	}
}

func impersonationAttributes(requestor user.Info, gv schema.GroupVersion, verb, resource, name string) *authorizer.AttributesRecord {
	return &authorizer.AttributesRecord{
		User:            requestor,
		Verb:            verb,
		APIGroup:        gv.Group,
		APIVersion:      gv.Version,
		Resource:        resource,
		Name:            name,
		ResourceRequest: true,
	}
}

type impersonateOnAttributes struct {
	mode string
	authorizer.Attributes
}

func (i *impersonateOnAttributes) GetVerb() string {
	return "impersonate-on:" + i.mode + ":" + i.Attributes.GetVerb()
}

func checkAuthorization(ctx context.Context, a authorizer.Authorizer, attributes authorizer.Attributes) error {
	authorized, reason, err := a.Authorize(ctx, attributes)

	// an authorizer like RBAC could encounter evaluation errors and still allow the request, so authorizer decision is checked before error here.
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

func ensureGroup(u *user.DefaultInfo, group string) {
	if slices.Contains(u.Groups, group) {
		return
	}

	// do not mutate a slice that we did not create
	groups := make([]string, 0, len(u.Groups)+1)
	groups = append(groups, u.Groups...)
	groups = append(groups, group)
	u.Groups = groups
}

func isServiceAccountUsername(username string) (namespace, name string, ok bool) {
	namespace, name, err := serviceaccount.SplitUsername(username)
	return namespace, name, err == nil
}

func isNodeUsername(username string) (string, bool) {
	const nodeUsernamePrefix = "system:node:"
	if !strings.HasPrefix(username, nodeUsernamePrefix) {
		return "", false
	}
	name := strings.TrimPrefix(username, nodeUsernamePrefix)
	if len(validation.ValidateNodeName(name, false)) != 0 {
		return "", false
	}
	return name, true
}

func requesterScheduledOnNode(requestor user.Info, username string) bool {
	nodeName, ok := isNodeUsername(username)
	if !ok {
		return false
	}
	if _, _, ok := isServiceAccountUsername(requestor.GetName()); !ok {
		return false
	}
	return len(getExtraValue(requestor, serviceaccount.PodNameKey)) != 0 &&
		getExtraValue(requestor, serviceaccount.NodeNameKey) == nodeName
}

func getExtraValue(u user.Info, key string) string {
	values := u.GetExtra()[key]
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func onlyUsernameSet(u user.Info) bool {
	return len(u.GetUID()) == 0 && len(u.GetGroups()) == 0 && len(u.GetExtra()) == 0
}

func processImpersonationHeaders(headers http.Header) (*user.DefaultInfo, error) {
	wantedUser := &user.DefaultInfo{}

	wantedUser.Name = headers.Get(authenticationv1.ImpersonateUserHeader)
	hasUser := len(wantedUser.Name) > 0

	wantedUser.UID = headers.Get(authenticationv1.ImpersonateUIDHeader)
	hasUID := len(wantedUser.UID) > 0

	hasGroups := false
	for _, group := range headers[authenticationv1.ImpersonateGroupHeader] {
		hasGroups = true
		wantedUser.Groups = append(wantedUser.Groups, group)
	}

	hasUserExtra := false
	for headerName, values := range headers {
		if !strings.HasPrefix(headerName, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
			continue
		}

		hasUserExtra = true
		extraKey := unescapeExtraKey(strings.ToLower(headerName[len(authenticationv1.ImpersonateUserExtraHeaderPrefix):]))

		if wantedUser.Extra == nil {
			wantedUser.Extra = map[string][]string{}
		}
		wantedUser.Extra[extraKey] = append(wantedUser.Extra[extraKey], values...)
	}

	if !hasUser && (hasUID || hasGroups || hasUserExtra) {
		return nil, fmt.Errorf("requested %#v without impersonating a user name", wantedUser)
	}

	if !hasUser {
		return nil, nil
	}

	// clear all the impersonation headers from the request to prevent downstream layers from knowing that impersonation was used
	// we do not want anything outside of file trying to behave differently based on if impersonation was used
	headers.Del(authenticationv1.ImpersonateUserHeader)
	headers.Del(authenticationv1.ImpersonateGroupHeader)
	headers.Del(authenticationv1.ImpersonateUIDHeader)
	for headerName := range headers {
		if strings.HasPrefix(headerName, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
			headers.Del(headerName)
		}
	}

	return wantedUser, nil
}

type impersonationModesTracker struct {
	modes    []impersonationMode
	idxCache *modeIndexCache
	impCache *impersonationCache
}

func newImpersonationModesTracker(a authorizer.Authorizer) *impersonationModesTracker {
	loggingAuthorizer := authorizer.AuthorizerFunc(func(ctx context.Context, attributes authorizer.Attributes) (authorizer.Decision, string, error) {
		decision, reason, err := a.Authorize(ctx, attributes)
		if klog.V(6).Enabled() {
			klog.V(6).InfoSDepth(3, "Impersonation authorization check",
				// impersonation is all about verb magic and the dump of the attributes may not make it obvious due to private fields
				"verb", attributes.GetVerb(),
				"attributes", attributes,
				"decision", decision,
				"reason", reason,
				"err", err,
			)
		}
		return decision, reason, err
	})
	return &impersonationModesTracker{
		modes:    allImpersonationModes(loggingAuthorizer),
		idxCache: newModeIndexCache(),
		impCache: newImpersonationCache(),
	}
}

func (t *impersonationModesTracker) getImpersonatedUser(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (outUser *impersonatedUserInfo, outErr error) {
	var errs []error

	// this outer cache covers the all the impersonation checks,
	// including those that need the request info, i.e. for constrained impersonation
	if impersonatedUser := t.impCache.get(wantedUser, attributes); impersonatedUser != nil {
		return impersonatedUser, nil
	}
	defer func() {
		if outErr != nil || outUser == nil {
			return
		}
		t.impCache.set(wantedUser, attributes, outUser)
	}()

	// try the last successful mode first to reduce the amortized cost of impersonation
	// we attempt all modes unless we short-circuit due to a successful impersonation
	modeIdx := t.idxCache.get(attributes)
	if modeIdx != -1 {
		impersonatedUser, err := t.modes[modeIdx](ctx, wantedUser, attributes)
		if err != nil {
			errs = append(errs, err)
		}
		if err == nil && impersonatedUser != nil {
			return impersonatedUser, nil
		}
	}

	for i, mode := range t.modes {
		if i == modeIdx {
			continue // skip already attempted mode
		}

		impersonatedUser, err := mode(ctx, wantedUser, attributes)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if impersonatedUser == nil {
			continue
		}
		t.idxCache.set(attributes, i)
		return impersonatedUser, nil
	}

	if err := utilerrors.NewAggregate(errs); err != nil {
		return nil, err // TODO decide if we just want to return the first (or maybe last) error
	}

	// this should not happen, but make sure we fail closed when no impersonation mode succeeded
	return nil, errors.New("all impersonation modes failed")
}

// modeIndexCache is a simple username -> impersonation mode cache that is based on the assumption
// that a particular user is likely to use a single mode of impersonation for all impersonated requests
// that they make.  it remembers which impersonation mode was last successful for a username, and tries
// that mode first for future impersonation checks.  this makes it so that the amortized cost of legacy
// impersonation remains the same, and the cost of constrained impersonation is one extra authorization
// check in additional to the existing checks of regular impersonation.
type modeIndexCache struct {
	cache *lru.Cache
}

func (c *modeIndexCache) get(attributes authorizer.Attributes) int {
	idx, ok := c.cache.Get(attributes.GetUser().GetName())
	if !ok {
		return -1
	}
	return idx.(int)
}

func (c *modeIndexCache) set(attributes authorizer.Attributes, idx int) {
	c.cache.Add(attributes.GetUser().GetName(), idx)
}

func newModeIndexCache() *modeIndexCache {
	return &modeIndexCache{
		cache: lru.New(1024), // hardcode a reasonably large size so we can remember many users without leaking memory
	}
}

type impersonationCache struct {
	cache *cache.Expiring
}

func (c *impersonationCache) get(wantedUser *user.DefaultInfo, attributes authorizer.Attributes) *impersonatedUserInfo {
	key, err := buildImpersonationCacheKey(wantedUser, attributes)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to build impersonation cache key: %w", err))
		return nil
	}
	impersonatedUser, ok := c.cache.Get(key)
	if !ok {
		return nil
	}
	return impersonatedUser.(*impersonatedUserInfo)
}

func (c *impersonationCache) set(wantedUser *user.DefaultInfo, attributes authorizer.Attributes, impersonatedUser *impersonatedUserInfo) {
	key, err := buildImpersonationCacheKey(wantedUser, attributes)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to build impersonation cache key: %w", err))
		return
	}
	c.cache.Set(key, impersonatedUser, 10*time.Second) // hardcode the same short TTL as used by TokenSuccessCacheTTL
}

// The attribute accessors known to cache key construction. If this fails to compile, the cache
// implementation may need to be updated.
var _ authorizer.Attributes = (interface {
	GetUser() user.Info
	GetVerb() string
	IsReadOnly() bool
	GetNamespace() string
	GetResource() string
	GetSubresource() string
	GetName() string
	GetAPIGroup() string
	GetAPIVersion() string
	IsResourceRequest() bool
	GetPath() string
	GetFieldSelector() (fields.Requirements, error)
	GetLabelSelector() (labels.Requirements, error)
})(nil)

// The user info accessors known to cache key construction. If this fails to compile, the cache
// implementation may need to be updated.
var _ user.Info = (interface {
	GetName() string
	GetUID() string
	GetGroups() []string
	GetExtra() map[string][]string
})(nil)

func buildImpersonationCacheKey(wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (string, error) {
	fieldSelector, err := attributes.GetFieldSelector()
	if err != nil {
		return "", err // if we do not fully understand the attributes, just skip caching altogether
	}

	labelSelector, err := attributes.GetLabelSelector()
	if err != nil {
		return "", err // if we do not fully understand the attributes, just skip caching altogether
	}

	b := newCacheKeyBuilder()

	addUser(b, wantedUser)
	addUser(b, attributes.GetUser())

	b.addLengthPrefixed(func(b *cacheKeyBuilder) {
		b.
			addString(attributes.GetVerb()).
			addBool(attributes.IsReadOnly()).
			addString(attributes.GetNamespace()).
			addString(attributes.GetResource()).
			addString(attributes.GetSubresource()).
			addString(attributes.GetName()).
			addString(attributes.GetAPIGroup()).
			addString(attributes.GetAPIVersion()).
			addBool(attributes.IsResourceRequest()).
			addString(attributes.GetPath())
	})

	b.addLengthPrefixed(func(b *cacheKeyBuilder) {
		for _, req := range fieldSelector {
			b.addStringSlice([]string{req.Field, string(req.Operator), req.Value})
		}
	})

	b.addLengthPrefixed(func(b *cacheKeyBuilder) {
		for _, req := range labelSelector {
			b.addString(req.String())
		}
	})

	return b.build()
}

func addUser(b *cacheKeyBuilder, u user.Info) {
	b.addLengthPrefixed(func(b *cacheKeyBuilder) {
		b.
			addString(u.GetName()).
			addString(u.GetUID()).
			addStringSlice(u.GetGroups()).
			addLengthPrefixed(func(b *cacheKeyBuilder) {
				extra := u.GetExtra()
				for _, key := range sets.StringKeySet(extra).List() {
					b.addString(key)
					b.addStringSlice(extra[key])
				}
			})
	})
}

type cacheKeyBuilder struct {
	builder *cryptobyte.Builder // TODO decide if we want to use a sync.Pool for the underlying buffer
}

func newCacheKeyBuilder() *cacheKeyBuilder { // TODO move and share with kubelet credential provider
	return &cacheKeyBuilder{builder: cryptobyte.NewBuilder(make([]byte, 0, 256))} // start with a reasonable size to avoid too many allocations
}

func (c *cacheKeyBuilder) addString(value string) *cacheKeyBuilder {
	c.addLengthPrefixed(func(c *cacheKeyBuilder) {
		c.builder.AddBytes([]byte(value))
	})
	return c
}

func (c *cacheKeyBuilder) addStringSlice(values []string) *cacheKeyBuilder {
	c.addLengthPrefixed(func(c *cacheKeyBuilder) {
		for _, v := range values {
			c.addString(v)
		}
	})
	return c
}

func (c *cacheKeyBuilder) addBool(value bool) *cacheKeyBuilder {
	var b byte
	if value {
		b = 1
	}
	c.builder.AddUint8(b)
	return c
}

type builderContinuation func(child *cacheKeyBuilder)

func (c *cacheKeyBuilder) addLengthPrefixed(f builderContinuation) {
	c.builder.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
		c := &cacheKeyBuilder{builder: b}
		f(c)
	})
}

func (c *cacheKeyBuilder) build() (string, error) {
	key, err := c.builder.Bytes()
	if err != nil {
		return "", err
	}
	// TODO decide if we want to use hmac.New(sha256.New, randomCacheKey) with a sync.Pool like the cached token authenticator
	hash := sha256.Sum256(key) // reduce the size of the cache key to keep the overall cache size small
	return fmt.Sprintf("%x", hash[:]), nil
}

func newImpersonationCache() *impersonationCache {
	return &impersonationCache{
		cache: cache.NewExpiring(),
	}
}

func forbidden(attributes authorizer.Attributes, w http.ResponseWriter, req *http.Request, err error, s runtime.NegotiatedSerializer) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	gvr := schema.GroupVersionResource{Group: attributes.GetAPIGroup(), Version: attributes.GetAPIVersion(), Resource: attributes.GetResource()}
	responsewriters.ErrorNegotiated(apierrors.NewForbidden(gvr.GroupResource(), attributes.GetName(), err), s, gvr.GroupVersion(), w, req)
}
