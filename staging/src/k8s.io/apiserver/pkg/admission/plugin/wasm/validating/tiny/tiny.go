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
		Username: r.Request.UserInfo.Username,
		Groups:   r.Request.UserInfo.Groups,
		Verb:     "magic-verb",
		Resource: r.Request.Resource.Resource,
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
			fmt.Sprintf("plugin saw uid %q", r.Request.UID),
			fmt.Sprintf("authorizer said %t because of %q", d.Allowed, d.Reason),
			fmt.Sprintf("plugin saw user %q in groups %q for resource %q",
				r.Request.UserInfo.Username, r.Request.UserInfo.Groups, r.Request.Resource.Resource),
		},
	}

	r.Request = nil
	buf, err := easyjson.Marshal(r)
	if err != nil {
		return plugin.ValidateResponse{}, err
	}

	return plugin.ValidateResponse{AdmissionReview: buf}, nil
}
