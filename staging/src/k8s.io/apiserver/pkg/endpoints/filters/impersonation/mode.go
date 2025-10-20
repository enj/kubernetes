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
	"fmt"
	"slices"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/kubernetes/pkg/apis/core/validation"
)

type impersonatedUserInfo struct {
	user       user.Info
	constraint string // the verb used in impersonationModeState.check that allowed this user to be impersonated
}

type impersonationMode func(ctx context.Context, key *impersonationCacheKey, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (*impersonatedUserInfo, error)
type constrainedImpersonationModeFilter func(wantedUser *user.DefaultInfo, requestor user.Info) bool

func allImpersonationModes(a authorizer.Authorizer) []impersonationMode {
	return []impersonationMode{
		associatedNodeImpersonationMode(a),
		arbitraryNodeImpersonationMode(a),
		serviceAccountImpersonationMode(a),
		userInfoImpersonationMode(a),
		legacyImpersonationMode(a),
	}
}

// TODO(enj): make another mode that like this one that does caching better for daemonsets
//  current idea is to make multiple authz checks with the original user extra and a compressed one
//  if both pass, then the compressed extra can be used to generate the cache key instead

func associatedNodeImpersonationMode(a authorizer.Authorizer) impersonationMode {
	return newConstrainedImpersonationMode(a, "associated-node",
		func(wantedUser *user.DefaultInfo, requestor user.Info) bool {
			return onlyUsernameSet(wantedUser) && requesterAssociatedWithNode(requestor, wantedUser.Name)
		},
	)
}

func arbitraryNodeImpersonationMode(a authorizer.Authorizer) impersonationMode {
	return newConstrainedImpersonationMode(a, "arbitrary-node",
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
	return newConstrainedImpersonationMode(a, "serviceaccount",
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
	return newConstrainedImpersonationMode(a, "user-info",
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
	m := newImpersonationModeState(a, "impersonate", false)
	return func(ctx context.Context, key *impersonationCacheKey, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (*impersonatedUserInfo, error) {
		requestor := attributes.GetUser()
		return m.check(ctx, key, wantedUser, requestor)
	}
}

func newConstrainedImpersonationMode(a authorizer.Authorizer, mode string, filter constrainedImpersonationModeFilter) impersonationMode {
	return (&constrainedImpersonationModeState{
		state:      newImpersonationModeState(a, "impersonate:"+mode, true),
		cache:      newImpersonationCache(false),
		authorizer: a,
		mode:       mode,
		filter:     filter,
	}).check
}

// TODO add comment
type constrainedImpersonationModeState struct {
	state *impersonationModeState
	// TODO comment
	cache      *impersonationCache
	authorizer authorizer.Authorizer
	mode       string
	filter     constrainedImpersonationModeFilter
}

func (c *constrainedImpersonationModeState) check(ctx context.Context, key *impersonationCacheKey, wantedUser *user.DefaultInfo, attributes authorizer.Attributes) (outUser *impersonatedUserInfo, outErr error) {
	requestor := attributes.GetUser()
	if !c.filter(wantedUser, requestor) {
		return nil, nil
	}

	if impersonatedUser := c.cache.get(key); impersonatedUser != nil {
		return impersonatedUser, nil
	}
	defer func() {
		if outErr != nil || outUser == nil {
			return
		}
		c.cache.set(key, outUser)
	}()

	if err := checkAuthorization(ctx, c.authorizer, &impersonateOnAttributes{mode: c.mode, Attributes: attributes}); err != nil {
		return nil, err
	}

	return c.state.check(ctx, key, wantedUser, requestor)
}

// TODO add comment
type impersonationModeState struct {
	authorizer                 authorizer.Authorizer
	verb                       string
	isConstrainedImpersonation bool

	usernameAndGroupGV schema.GroupVersion
	constraint         string

	// TODO add more detailed comments here
	// the inner cache covers the impersonation checks that are not dependent on the request info
	cache *impersonationCache
}

func newImpersonationModeState(a authorizer.Authorizer, verb string, isConstrainedImpersonation bool) *impersonationModeState {
	usernameAndGroupGV := authenticationv1.SchemeGroupVersion
	constraint := verb
	if !isConstrainedImpersonation {
		usernameAndGroupGV = corev1.SchemeGroupVersion
		constraint = ""
	}
	return &impersonationModeState{
		authorizer:                 a,
		verb:                       verb,
		isConstrainedImpersonation: isConstrainedImpersonation,

		usernameAndGroupGV: usernameAndGroupGV,
		constraint:         constraint,
		cache:              newImpersonationCache(true),
	}
}

func (m *impersonationModeState) check(ctx context.Context, key *impersonationCacheKey, wantedUser *user.DefaultInfo, requestor user.Info) (outUser *impersonatedUserInfo, outErr error) {
	if impersonatedUser := m.cache.get(key); impersonatedUser != nil {
		return impersonatedUser, nil
	}
	defer func() {
		if outErr != nil || outUser == nil {
			return
		}
		m.cache.set(key, outUser)
	}()

	actualUser := *wantedUser

	usernameAttributes := impersonationAttributes(requestor, m.usernameAndGroupGV, m.verb, "users", wantedUser.Name)
	if m.isConstrainedImpersonation {
		if name, ok := isNodeUsername(wantedUser.Name); ok {
			usernameAttributes.Resource = "nodes"
			usernameAttributes.Name = name

			// this should be impossible to reach but check just in case
			if len(wantedUser.Groups) != 0 {
				return nil, responsewriters.ForbiddenStatusError(usernameAttributes, fmt.Sprintf("when impersonating a node, cannot impersonate groups %q", wantedUser.Groups))
			}

			actualUser.Groups = []string{user.NodesGroup}
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
	if err := checkAuthorization(ctx, m.authorizer, usernameAttributes); err != nil {
		return nil, err
	}

	if len(wantedUser.UID) > 0 {
		uidAttributes := impersonationAttributes(requestor, authenticationv1.SchemeGroupVersion, m.verb, "uids", wantedUser.UID)
		if err := checkAuthorization(ctx, m.authorizer, uidAttributes); err != nil {
			return nil, err
		}
	}

	groupAttributes := impersonationAttributes(requestor, m.usernameAndGroupGV, m.verb, "groups", "")
	for _, group := range wantedUser.Groups {
		groupAttributes.Name = group
		if err := checkAuthorization(ctx, m.authorizer, groupAttributes); err != nil {
			return nil, err
		}
	}

	extraAttributes := impersonationAttributes(requestor, authenticationv1.SchemeGroupVersion, m.verb, "userextras", "")
	for key, values := range wantedUser.Extra {
		extraAttributes.Subresource = key
		for _, value := range values {
			extraAttributes.Name = value
			if err := checkAuthorization(ctx, m.authorizer, extraAttributes); err != nil {
				return nil, err
			}
		}
	}

	if actualUser.Name == user.Anonymous {
		ensureGroup(&actualUser, user.AllUnauthenticated)
	} else {
		ensureGroup(&actualUser, user.AllAuthenticated)
	}

	return &impersonatedUserInfo{user: &actualUser, constraint: m.constraint}, nil
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

func requesterAssociatedWithNode(requestor user.Info, username string) bool {
	nodeName, ok := isNodeUsername(username)
	if !ok {
		return false
	}
	if _, _, ok := isServiceAccountUsername(requestor.GetName()); !ok {
		return false
	}
	return getExtraValue(requestor, serviceaccount.NodeNameKey) == nodeName
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
