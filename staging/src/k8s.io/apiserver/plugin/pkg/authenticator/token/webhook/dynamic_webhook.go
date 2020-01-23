package webhook

import "k8s.io/apiserver/pkg/authentication/authenticator"

func NewDynamic(implicitAuds authenticator.Audiences) (authenticator.Token, func(stopCh <-chan struct{})) {
	return nil, nil
}
