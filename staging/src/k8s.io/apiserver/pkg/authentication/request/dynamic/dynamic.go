package dynamic

import "k8s.io/apiserver/pkg/authentication/authenticator"

func New(implicitAuds authenticator.Audiences) (authenticator.Request, func(stopCh <-chan struct{})) {
	return nil, nil
}
