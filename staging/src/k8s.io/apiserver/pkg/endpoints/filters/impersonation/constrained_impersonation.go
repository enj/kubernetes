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

package impersonation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server/httplog"
	"k8s.io/klog/v2"
)

// TODO add metrics

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
		attributes, err := filters.GetAuthorizerAttributes(ctx)
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
			responsewriters.RespondWithError(attributes, w, req, err, s)
			return
		}

		req = req.WithContext(request.WithUser(ctx, impersonatedUser.user))
		httplog.LogOf(req, w).Addf("%v is impersonating %v", userString(requestor), userString(impersonatedUser.user))
		audit.LogImpersonatedUser(audit.WithAuditContext(ctx), impersonatedUser.user, impersonatedUser.constraint)

		handler.ServeHTTP(w, req)
	})
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
	// this outer cache covers the all the impersonation checks,
	// including those that need the request info, i.e. for constrained impersonation
	key := &impersonationCacheKey{wantedUser: wantedUser, attributes: attributes}
	if impersonatedUser := t.impCache.get(key, false); impersonatedUser != nil {
		return impersonatedUser, nil
	}
	defer func() {
		if outErr != nil || outUser == nil {
			return
		}
		t.impCache.set(key, false, outUser)
	}()

	var firstErr error

	// try the last successful mode first to reduce the amortized cost of impersonation
	// we attempt all modes unless we short-circuit due to a successful impersonation
	modeIdx := t.idxCache.get(attributes)
	if modeIdx != -1 {
		impersonatedUser, err := t.modes[modeIdx](ctx, key, wantedUser, attributes)
		if err == nil && impersonatedUser != nil {
			return impersonatedUser, nil
		}
		firstErr = err
	}

	for i, mode := range t.modes {
		if i == modeIdx {
			continue // skip already attempted mode
		}

		impersonatedUser, err := mode(ctx, key, wantedUser, attributes)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if impersonatedUser == nil {
			continue
		}
		t.idxCache.set(attributes, i)
		return impersonatedUser, nil
	}

	if firstErr != nil {
		return nil, firstErr
	}

	// this should not happen, but make sure we fail closed when no impersonation mode succeeded
	return nil, errors.New("all impersonation modes failed")
}
