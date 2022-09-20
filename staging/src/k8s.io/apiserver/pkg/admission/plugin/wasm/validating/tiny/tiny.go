//go:build tinygo.wasm

package main

import (
	"context"

	"k8s.io/apiserver/pkg/admission/plugin/wasm/validating/plugin"
)

func main() {
	plugin.RegisterValidation(p{})

}

type p struct{}

func (m p) Validate(ctx context.Context, request plugin.ValidateRequest) (plugin.ValidateResponse, error) {
	return plugin.ValidateResponse{AdmissionReview: []byte(`
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "response": {
    "uid": "<value from request.uid>",
    "warnings": ["hello", "there"],
    "allowed": true
  }
}
`)}, nil
}
