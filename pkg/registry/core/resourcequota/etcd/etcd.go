/*
Copyright 2015 The Kubernetes Authors.

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

package etcd

import (
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/rest"
	"k8s.io/kubernetes/pkg/genericapiserver"
	"k8s.io/kubernetes/pkg/registry/core/resourcequota"
	"k8s.io/kubernetes/pkg/registry/generic/registry"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/storage"
	"k8s.io/kubernetes/pkg/util/restoptions"
)

type REST struct {
	*registry.Store
}

// NewREST returns a RESTStorage object that will work against resource quotas.
func NewREST(optsGetter genericapiserver.RESTOptionsGetter) (*REST, *StatusREST) {
	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &api.ResourceQuota{} },
		NewListFunc: func() runtime.Object { return &api.ResourceQuotaList{} },
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*api.ResourceQuota).Name, nil
		},
		PredicateFunc:     resourcequota.MatchResourceQuota,
		QualifiedResource: api.Resource("resourcequotas"),

		CreateStrategy:      resourcequota.Strategy,
		UpdateStrategy:      resourcequota.Strategy,
		DeleteStrategy:      resourcequota.Strategy,
		ReturnDeletedObject: true,
	}
	restoptions.ApplyOptions(optsGetter, store, storage.NoTriggerPublisher)

	statusStore := *store
	statusStore.UpdateStrategy = resourcequota.StatusStrategy

	return &REST{store}, &StatusREST{store: &statusStore}
}

// StatusREST implements the REST endpoint for changing the status of a resourcequota.
type StatusREST struct {
	store *registry.Store
}

func (r *StatusREST) New() runtime.Object {
	return &api.ResourceQuota{}
}

// Get retrieves the object from the storage. It is required to support Patch.
func (r *StatusREST) Get(ctx api.Context, name string) (runtime.Object, error) {
	return r.store.Get(ctx, name)
}

// Update alters the status subset of an object.
func (r *StatusREST) Update(ctx api.Context, name string, objInfo rest.UpdatedObjectInfo) (runtime.Object, bool, error) {
	return r.store.Update(ctx, name, objInfo)
}
