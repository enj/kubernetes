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
	"crypto/sha256"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/cache"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/utils/lru"
)

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

func (c *impersonationCache) get(k *impersonationCacheKey) *impersonatedUserInfo {
	key, err := k.stringKey()
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

func (c *impersonationCache) set(k *impersonationCacheKey, impersonatedUser *impersonatedUserInfo) {
	key, err := k.stringKey()
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

type impersonationCacheKey struct {
	wantedUser *user.DefaultInfo
	attributes authorizer.Attributes

	// lazily calculated values at point of use
	key string
	err error
}

func (k *impersonationCacheKey) stringKey() (out string, outErr error) {
	if len(k.key) != 0 || k.err != nil {
		return k.key, k.err
	}

	defer func() { k.key, k.err = out, outErr }()

	fieldSelector, err := k.attributes.GetFieldSelector()
	if err != nil {
		return "", err // if we do not fully understand the attributes, just skip caching altogether
	}

	labelSelector, err := k.attributes.GetLabelSelector()
	if err != nil {
		return "", err // if we do not fully understand the attributes, just skip caching altogether
	}

	requestor := k.attributes.GetUser()

	// the chance of a hash collision is impractically small, but the only way that would lead to a
	// privilege escalation is if you could get the cache key of a different user.  if you somehow
	// get a collision with your own username, you already have that permission since we only set
	// values in the cache after a successful impersonation.  Thus, we include the requestor
	// username in the cache key.  It is safe to assume that a user has no control over their own
	// username since that is controlled by the authenticator.  Even though many of the other inputs
	// are under the control of the requestor, they cannot explode the cache due to the hashing.
	b := newCacheKeyBuilder(requestor.GetName()) // TODO maybe limit number of cache entries for a given user

	addUser(b, k.wantedUser)
	addUser(b, requestor)

	b.addLengthPrefixed(func(b *cacheKeyBuilder) {
		b.
			addString(k.attributes.GetVerb()).
			addBool(k.attributes.IsReadOnly()).
			addString(k.attributes.GetNamespace()).
			addString(k.attributes.GetResource()).
			addString(k.attributes.GetSubresource()).
			addString(k.attributes.GetName()).
			addString(k.attributes.GetAPIGroup()).
			addString(k.attributes.GetAPIVersion()).
			addBool(k.attributes.IsResourceRequest()).
			addString(k.attributes.GetPath())
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
	namespace string              // in the programming sense, not the Kubernetes concept
	builder   *cryptobyte.Builder // TODO decide if we want to use a sync.Pool for the underlying buffer
}

func newCacheKeyBuilder(namespace string) *cacheKeyBuilder { // TODO move and share with kubelet credential provider
	return &cacheKeyBuilder{namespace: namespace, builder: cryptobyte.NewBuilder(make([]byte, 0, 384))} // start with a reasonable size to avoid too many allocations
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
		c := &cacheKeyBuilder{namespace: c.namespace, builder: b}
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
	return fmt.Sprintf("%x/%s", hash[:], c.namespace), nil
}

func newImpersonationCache() *impersonationCache {
	return &impersonationCache{
		cache: cache.NewExpiring(),
	}
}
