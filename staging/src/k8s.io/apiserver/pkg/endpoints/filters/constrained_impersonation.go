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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
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

		impersonatedUser, err := tracker.getImpersonatedUser(ctx, wantedUser, attributes)
		if err != nil {
			klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "err", err)
			forbidden(attributes, w, req, err, s)
			return
		}

		req = req.WithContext(request.WithUser(ctx, impersonatedUser))
		httplog.LogOf(req, w).Addf("%v is impersonating %v", userString(attributes.GetUser()), userString(impersonatedUser))
		audit.LogImpersonatedUser(audit.WithAuditContext(ctx), impersonatedUser)

		handler.ServeHTTP(w, req)
	})
}

type impersonationMode func(context.Context, *user.DefaultInfo, authorizer.Attributes) (user.Info, error)

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
	userInfoCheck := buildImpersonationMode(a, "impersonate:scheduled-node", authenticationv1.SchemeGroupVersion, true)
	return func(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (user.Info, error) {
		if !requesterScheduledOnNode(attributes.GetUser(), wantedUser.Name) {
			return nil, nil
		}
		if err := checkAuthorization(ctx, a, &impersonateOnAttributes{Attributes: attributes}); err != nil {
			return nil, err
		}
		return userInfoCheck(ctx, wantedUser, attributes)
	}
}

func nodeImpersonationMode(a authorizer.Authorizer) impersonationMode {
	userInfoCheck := buildImpersonationMode(a, "impersonate:node", authenticationv1.SchemeGroupVersion, true)
	return func(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (user.Info, error) {
		if _, ok := isNodeUsername(wantedUser.Name); !ok {
			return nil, nil
		}
		if err := checkAuthorization(ctx, a, &impersonateOnAttributes{Attributes: attributes}); err != nil {
			return nil, err
		}
		return userInfoCheck(ctx, wantedUser, attributes)
	}
}

func serviceAccountImpersonationMode(a authorizer.Authorizer) impersonationMode {
	userInfoCheck := buildImpersonationMode(a, "impersonate:serviceaccount", authenticationv1.SchemeGroupVersion, false)
	return func(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (user.Info, error) {
		if _, _, ok := isServiceAccountUsername(wantedUser.Name); !ok {
			return nil, nil
		}
		if err := checkAuthorization(ctx, a, &impersonateOnAttributes{Attributes: attributes}); err != nil {
			return nil, err
		}
		return userInfoCheck(ctx, wantedUser, attributes)
	}
}

func userInfoImpersonationMode(a authorizer.Authorizer) impersonationMode {
	userInfoCheck := buildImpersonationMode(a, "impersonate:user-info", authenticationv1.SchemeGroupVersion, false)
	return func(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (user.Info, error) {
		// nodes and service accounts cannot be impersonated in this mode
		if _, ok := isNodeUsername(wantedUser.Name); ok {
			return nil, nil
		}
		if _, _, ok := isServiceAccountUsername(wantedUser.Name); ok {
			return nil, nil
		}
		if err := checkAuthorization(ctx, a, &impersonateOnAttributes{Attributes: attributes}); err != nil {
			return nil, err
		}
		return userInfoCheck(ctx, wantedUser, attributes)
	}
}

func legacyImpersonationMode(a authorizer.Authorizer) impersonationMode {
	return buildImpersonationMode(a, "impersonate", corev1.SchemeGroupVersion, false)
}

func buildImpersonationMode(a authorizer.Authorizer, verb string, gv schema.GroupVersion, supportsNodeImpersonation bool) impersonationMode {
	return func(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (user.Info, error) {
		requestor := attributes.GetUser()
		actualUser := *wantedUser

		usernameAttributes := impersonationAttributes(requestor, gv, verb, "users", wantedUser.Name)
		if namespace, name, ok := isServiceAccountUsername(wantedUser.Name); ok {
			usernameAttributes.Resource = "serviceaccounts"
			usernameAttributes.Namespace = namespace
			usernameAttributes.Name = name

			if len(wantedUser.Groups) == 0 {
				// if groups aren't specified for a service account, we know the groups because it is a fixed mapping.  Add them
				actualUser.Groups = serviceaccount.MakeGroupNames(namespace)
			}
		}
		// TODO node as a first class concept in impersonation is new, how strict do we want to be?
		if supportsNodeImpersonation {
			if name, ok := isNodeUsername(wantedUser.Name); ok {
				usernameAttributes.Resource = "nodes"
				usernameAttributes.Name = name

				if len(wantedUser.Groups) == 0 {
					actualUser.Groups = []string{user.NodesGroup}
				}
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

		groupAttributes := impersonationAttributes(requestor, gv, verb, "groups", "")
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

		return &actualUser, nil
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
	authorizer.Attributes
}

func (i *impersonateOnAttributes) GetVerb() string {
	return "impersonate-on:" + i.Attributes.GetVerb()
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
	return name, false
}

func requesterScheduledOnNode(u user.Info, username string) bool {
	nodeName, ok := isNodeUsername(username)
	if !ok {
		return false
	}
	if _, _, ok := isServiceAccountUsername(u.GetName()); !ok {
		return false
	}
	if len(getExtraValue(u, serviceaccount.PodNameKey)) == 0 {
		return false
	}
	return getExtraValue(u, serviceaccount.NodeNameKey) == nodeName
}

func getExtraValue(u user.Info, key string) string {
	values := u.GetExtra()[key]
	if len(values) != 1 {
		return ""
	}
	return values[0]
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
	modes []impersonationMode
	cache *modeIndexCache
}

func newImpersonationModesTracker(a authorizer.Authorizer) *impersonationModesTracker {
	return &impersonationModesTracker{
		modes: allImpersonationModes(a),
		cache: newModeIndexCache(),
	}
}

func (t *impersonationModesTracker) getImpersonatedUser(ctx context.Context, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (user.Info, error) {
	var errs []error

	modeIdx := t.cache.get(attributes) // TODO add support for fancier cache that maps attributes+wantedUser to impersonatedUser
	if modeIdx != -1 {
		impersonatedUser, err := t.modes[modeIdx](ctx, wantedUser, attributes)
		if err != nil {
			errs = append(errs, err)
		}
		if impersonatedUser != nil {
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
		t.cache.set(attributes, i)
		return impersonatedUser, nil
	}

	if err := utilerrors.NewAggregate(errs); err != nil {
		return nil, err
	}

	// this should not happen, but make sure we fail closed when no impersonation mode succeeded
	return nil, errors.New("all impersonation modes failed")
}

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

func (c *modeIndexCache) set(attributes authorizer.Attributes, value int) {
	c.cache.Add(attributes.GetUser().GetName(), value)
}

func newModeIndexCache() *modeIndexCache {
	return &modeIndexCache{
		cache: lru.New(1024),
	}
}

func forbidden(attributes authorizer.Attributes, w http.ResponseWriter, req *http.Request, err error, s runtime.NegotiatedSerializer) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	gvr := schema.GroupVersionResource{Group: attributes.GetAPIGroup(), Version: attributes.GetAPIVersion(), Resource: attributes.GetResource()}
	responsewriters.ErrorNegotiated(apierrors.NewForbidden(gvr.GroupResource(), attributes.GetName(), err), s, gvr.GroupVersion(), w, req)
}
