package filters

import (
	"net/http"

	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/audit/policy"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// WithAuditAnnotations decorates a http.Handler with a map that is merged with
// the audit.Event.Annotations map.  This allows layers that run before WithAudit
// (such as authentication) to assert annotations.
// If sink or audit policy is nil, no decoration takes place.
func WithAuditAnnotations(handler http.Handler, sink audit.Sink, policy policy.Checker) http.Handler {
	// no need to wrap if auditing is disabled
	if sink == nil || policy == nil {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// insert a non-nil map that is available to early request handlers
		annotations := map[string]string{}
		req = req.WithContext(genericapirequest.WithAuditAnnotations(req.Context(), annotations))
		handler.ServeHTTP(w, req)
	})
}
