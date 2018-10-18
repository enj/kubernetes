package etcd

import (
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coreos/etcd/clientv3"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"
	cacheddiscovery "k8s.io/client-go/discovery/cached"
	clientset "k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
	"k8s.io/kubernetes/cmd/kube-apiserver/app/options"
	"k8s.io/kubernetes/test/integration"
	"k8s.io/kubernetes/test/integration/framework"

	// install all APIs
	_ "k8s.io/kubernetes/pkg/master"
)

func StartRealMasterOrDie(t *testing.T) (*restclient.Config, clientv3.KV, meta.RESTMapper, []Resource, func()) {
	certDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}

	_, defaultServiceClusterIPRange, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	listener, _, err := genericapiserveroptions.CreateListener("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	kubeAPIServerOptions := options.NewServerRunOptions()
	kubeAPIServerOptions.InsecureServing.BindPort = 0
	kubeAPIServerOptions.SecureServing.Listener = listener
	kubeAPIServerOptions.SecureServing.ServerCert.CertDirectory = certDir
	kubeAPIServerOptions.Etcd.StorageConfig.ServerList = []string{framework.GetEtcdURL()}
	kubeAPIServerOptions.Etcd.DefaultStorageMediaType = runtime.ContentTypeJSON // force json we can easily interpret the result in etcd
	kubeAPIServerOptions.ServiceClusterIPRange = *defaultServiceClusterIPRange
	kubeAPIServerOptions.Authorization.Modes = []string{"RBAC"}
	kubeAPIServerOptions.Admission.GenericAdmission.DisablePlugins = []string{"ServiceAccount"}
	completedOptions, err := app.Complete(kubeAPIServerOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := kubeAPIServerOptions.APIEnablement.RuntimeConfig.Set("api/all=true"); err != nil {
		t.Fatal(err)
	}

	kubeAPIServer, err := app.CreateServerChain(completedOptions, wait.NeverStop)
	if err != nil {
		t.Fatal(err)
	}
	kubeClientConfig := restclient.CopyConfig(kubeAPIServer.LoopbackClientConfig)

	go func() {
		// Catch panics that occur in this go routine so we get a comprehensible failure
		defer func() {
			if err := recover(); err != nil {
				t.Errorf("Unexpected panic trying to start API master: %#v", err)
			}
		}()

		if err := kubeAPIServer.PrepareRun().Run(wait.NeverStop); err != nil {
			t.Fatal(err)
		}
	}()

	kubeClient := clientset.NewForConfigOrDie(kubeClientConfig)

	lastHealth := ""
	if err := wait.PollImmediate(time.Second, time.Minute, func() (done bool, err error) {
		// wait for the server to be healthy
		result := kubeClient.RESTClient().Get().AbsPath("/healthz").Do()
		content, _ := result.Raw()
		lastHealth = string(content)
		if errResult := result.Error(); errResult != nil {
			t.Log(errResult)
			return false, nil
		}
		var status int
		result.StatusCode(&status)
		return status == http.StatusOK, nil
	}); err != nil {
		t.Log(lastHealth)
		t.Fatal(err)
	}

	// this test makes lots of requests, don't be slow
	kubeClientConfig.QPS = 99999
	kubeClientConfig.Burst = 9999

	kvClient, err := integration.GetEtcdKVClient(kubeAPIServerOptions.Etcd.StorageConfig)
	if err != nil {
		t.Fatal(err)
	}

	// force cached discovery reset
	discoveryClient := cacheddiscovery.NewMemCacheClient(kubeClient.Discovery())
	restMapper := restmapper.NewDeferredDiscoveryRESTMapper(discoveryClient)
	restMapper.Reset()

	serverResources, err := kubeClient.Discovery().ServerResources()
	if err != nil {
		t.Fatal(err)
	}

	return kubeClientConfig, kvClient, restMapper, getResources(t, serverResources), func() { _ = os.RemoveAll(certDir) }
}

type Resource struct {
	Gvk                 schema.GroupVersionKind
	Gvr                 schema.GroupVersionResource
	Namespaced          bool
	HasDeleteCollection bool
}

func getResources(t *testing.T, serverResources []*metav1.APIResourceList) []Resource {
	var resources []Resource

	for _, discoveryGroup := range serverResources {
		for _, discoveryResource := range discoveryGroup.APIResources {
			// this is a subresource, skip it
			if strings.Contains(discoveryResource.Name, "/") {
				continue
			}
			hasCreate := false
			hasGet := false
			hasDeleteCollection := false
			for _, verb := range discoveryResource.Verbs {
				if verb == "get" {
					hasGet = true
				}
				if verb == "create" {
					hasCreate = true
				}
				if verb == "deletecollection" {
					hasDeleteCollection = true
				}
			}
			if !(hasCreate && hasGet) {
				continue
			}

			resourceGV, err := schema.ParseGroupVersion(discoveryGroup.GroupVersion)
			if err != nil {
				t.Fatal(err)
			}
			gvk := resourceGV.WithKind(discoveryResource.Kind)
			if len(discoveryResource.Group) > 0 || len(discoveryResource.Version) > 0 {
				gvk = schema.GroupVersionKind{
					Group:   discoveryResource.Group,
					Version: discoveryResource.Version,
					Kind:    discoveryResource.Kind,
				}
			}
			gvr := resourceGV.WithResource(discoveryResource.Name)

			resources = append(resources, Resource{
				Gvk:                 gvk,
				Gvr:                 gvr,
				Namespaced:          discoveryResource.Namespaced,
				HasDeleteCollection: hasDeleteCollection,
			})
		}
	}

	return resources
}
