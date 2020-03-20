/*
Copyright 2020 The Kubernetes Authors.

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

package audit

import (
	"context"

	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// The key type is unexported to prevent collisions
type key int

const (
	// auditAnnotationsKey is the context key for the audit annotations.
	auditAnnotationsKey key = iota
)

// annotations = *[]annotation instead of a map to preserve order of insertions
type annotation struct {
	key, value string
}

func WithAuditAnnotations(parent context.Context) context.Context {
	// this should never really happen, but prevent double registration of this slice
	if _, ok := parent.Value(auditAnnotationsKey).(*[]annotation); ok {
		return parent
	}

	var annotations []annotation // avoid allocations until we actually need it
	return genericapirequest.WithValue(parent, auditAnnotationsKey, &annotations)
}

func AddAuditAnnotation(ctx context.Context, key, value string) {
	// use the audit event directly if we have it
	if ae := genericapirequest.AuditEventFrom(ctx); ae != nil {
		LogAnnotation(ae, key, value)
		return
	}

	annotations, ok := ctx.Value(auditAnnotationsKey).(*[]annotation)
	if !ok {
		return // auditing is disabled
	}

	*annotations = append(*annotations, annotation{key: key, value: value})
}

// this is private to prevent reads/write to the slice from outside of this package
// the audit event should be directly read to get access to the annotations
func auditAnnotationsFrom(ctx context.Context) []annotation {
	annotations, ok := ctx.Value(auditAnnotationsKey).(*[]annotation)
	if !ok {
		return nil // auditing is disabled
	}

	return *annotations
}
