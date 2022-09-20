//go:build tinygo.wasm

package main

import (
	"context"
	"fmt"

	"github.com/mailru/easyjson"
	"k8s.io/apiserver/pkg/admission/plugin/wasm/validating/plugin"
)

func main() {
	plugin.RegisterValidation(p{a: plugin.NewSubjectAccessReview()})
}

type p struct {
	a plugin.SubjectAccessReview
}

func (m p) Validate(ctx context.Context, request plugin.ValidateRequest) (plugin.ValidateResponse, error) {
	r := &AdmissionReview{}
	if err := easyjson.Unmarshal(request.AdmissionReview, r); err != nil {
		return plugin.ValidateResponse{}, err
	}

	d, err := m.a.Authorize(ctx, plugin.SubjectAccessReviewSpec{
		Username: "bob",
		Verb:     "get",
		Resource: "pods",
	})
	if err != nil {
		return plugin.ValidateResponse{}, err
	}

	r.Response = &AdmissionResponse{
		UID:              r.Request.UID,
		Allowed:          true,
		Result:           nil,
		AuditAnnotations: nil,
		Warnings: []string{
			fmt.Sprintf("plugin saw uid %s", r.Request.UID),
			fmt.Sprintf("authorizer said %t because of %s", d.Allowed, d.Reason),
		},
	}

	r.Request = nil
	buf, err := easyjson.Marshal(r)
	if err != nil {
		return plugin.ValidateResponse{}, err
	}

	return plugin.ValidateResponse{AdmissionReview: buf}, nil
}
