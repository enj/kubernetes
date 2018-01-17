/*
Copyright 2016 The Kubernetes Authors.

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

package v1beta1

import (
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Pod Security Policy governs the ability to make requests that affect the Security Context
// that will be applied to a pod and container.
type PodSecurityPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// spec defines the policy enforced.
	// +optional
	Spec PodSecurityPolicySpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

// Pod Security Policy Spec defines the policy enforced.
type PodSecurityPolicySpec struct {
	// privileged determines if a pod can request to be run as privileged.
	// +optional
	Privileged bool `json:"privileged,omitempty" protobuf:"varint,1,opt,name=privileged"`
	// DefaultAddCapabilities is the default set of capabilities that will be added to the container
	// unless the pod spec specifically drops the capability.  You may not list a capability in both
	// DefaultAddCapabilities and RequiredDropCapabilities. Capabilities added here are implicitly
	// allowed, and need not be included in the AllowedCapabilities list.
	// +optional
	DefaultAddCapabilities []v1.Capability `json:"defaultAddCapabilities,omitempty" protobuf:"bytes,2,rep,name=defaultAddCapabilities,casttype=k8s.io/api/core/v1.Capability"`
	// RequiredDropCapabilities are the capabilities that will be dropped from the container.  These
	// are required to be dropped and cannot be added.
	// +optional
	RequiredDropCapabilities []v1.Capability `json:"requiredDropCapabilities,omitempty" protobuf:"bytes,3,rep,name=requiredDropCapabilities,casttype=k8s.io/api/core/v1.Capability"`
	// AllowedCapabilities is a list of capabilities that can be requested to add to the container.
	// Capabilities in this field may be added at the pod author's discretion.
	// You must not list a capability in both AllowedCapabilities and RequiredDropCapabilities.
	// +optional
	AllowedCapabilities []v1.Capability `json:"allowedCapabilities,omitempty" protobuf:"bytes,4,rep,name=allowedCapabilities,casttype=k8s.io/api/core/v1.Capability"`
	// volumes is a white list of allowed volume plugins.  Empty indicates that all plugins
	// may be used.
	// +optional
	Volumes []FSType `json:"volumes,omitempty" protobuf:"bytes,5,rep,name=volumes,casttype=FSType"`
	// hostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
	// +optional
	HostNetwork bool `json:"hostNetwork,omitempty" protobuf:"varint,6,opt,name=hostNetwork"`
	// hostPorts determines which host port ranges are allowed to be exposed.
	// +optional
	HostPorts []HostPortRange `json:"hostPorts,omitempty" protobuf:"bytes,7,rep,name=hostPorts"`
	// hostPID determines if the policy allows the use of HostPID in the pod spec.
	// +optional
	HostPID bool `json:"hostPID,omitempty" protobuf:"varint,8,opt,name=hostPID"`
	// hostIPC determines if the policy allows the use of HostIPC in the pod spec.
	// +optional
	HostIPC bool `json:"hostIPC,omitempty" protobuf:"varint,9,opt,name=hostIPC"`
	// seLinux is the strategy that will dictate the allowable labels that may be set.
	SELinux SELinuxStrategyOptions `json:"seLinux" protobuf:"bytes,10,opt,name=seLinux"`
	// runAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
	RunAsUser RunAsUserStrategyOptions `json:"runAsUser" protobuf:"bytes,11,opt,name=runAsUser"`
	// SupplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
	SupplementalGroups SupplementalGroupsStrategyOptions `json:"supplementalGroups" protobuf:"bytes,12,opt,name=supplementalGroups"`
	// FSGroup is the strategy that will dictate what fs group is used by the SecurityContext.
	FSGroup FSGroupStrategyOptions `json:"fsGroup" protobuf:"bytes,13,opt,name=fsGroup"`
	// ReadOnlyRootFilesystem when set to true will force containers to run with a read only root file
	// system.  If the container specifically requests to run with a non-read only root file system
	// the PSP should deny the pod.
	// If set to false the container may run with a read only root file system if it wishes but it
	// will not be forced to.
	// +optional
	ReadOnlyRootFilesystem bool `json:"readOnlyRootFilesystem,omitempty" protobuf:"varint,14,opt,name=readOnlyRootFilesystem"`
	// DefaultAllowPrivilegeEscalation controls the default setting for whether a
	// process can gain more privileges than its parent process.
	// +optional
	DefaultAllowPrivilegeEscalation *bool `json:"defaultAllowPrivilegeEscalation,omitempty" protobuf:"varint,15,opt,name=defaultAllowPrivilegeEscalation"`
	// AllowPrivilegeEscalation determines if a pod can request to allow
	// privilege escalation. If unspecified, defaults to true.
	// +optional
	AllowPrivilegeEscalation *bool `json:"allowPrivilegeEscalation,omitempty" protobuf:"varint,16,opt,name=allowPrivilegeEscalation"`
	// is a white list of allowed host paths. Empty indicates that all host paths may be used.
	// +optional
	AllowedHostPaths []AllowedHostPath `json:"allowedHostPaths,omitempty" protobuf:"bytes,17,rep,name=allowedHostPaths"`
	// AllowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
	// Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
	// is allowed in the "Volumes" field.
	// +optional
	AllowedFlexVolumes []AllowedFlexVolume `json:"allowedFlexVolumes,omitempty" protobuf:"bytes,18,rep,name=allowedFlexVolumes"`
}

// defines the host volume conditions that will be enabled by a policy
// for pods to use. It requires the path prefix to be defined.
type AllowedHostPath struct {
	// is the path prefix that the host volume must match.
	// It does not support `*`.
	// Trailing slashes are trimmed when validating the path prefix with a host path.
	//
	// Examples:
	// `/foo` would allow `/foo`, `/foo/` and `/foo/bar`
	// `/foo` would not allow `/food` or `/etc/foo`
	PathPrefix string `json:"pathPrefix,omitempty" protobuf:"bytes,1,rep,name=pathPrefix"`
}

// FS Type gives strong typing to different file systems that are used by volumes.
type FSType string

var (
	AzureFile             FSType = "azureFile"
	Flocker               FSType = "flocker"
	FlexVolume            FSType = "flexVolume"
	HostPath              FSType = "hostPath"
	EmptyDir              FSType = "emptyDir"
	GCEPersistentDisk     FSType = "gcePersistentDisk"
	AWSElasticBlockStore  FSType = "awsElasticBlockStore"
	GitRepo               FSType = "gitRepo"
	Secret                FSType = "secret"
	NFS                   FSType = "nfs"
	ISCSI                 FSType = "iscsi"
	Glusterfs             FSType = "glusterfs"
	PersistentVolumeClaim FSType = "persistentVolumeClaim"
	RBD                   FSType = "rbd"
	Cinder                FSType = "cinder"
	CephFS                FSType = "cephFS"
	DownwardAPI           FSType = "downwardAPI"
	FC                    FSType = "fc"
	ConfigMap             FSType = "configMap"
	Quobyte               FSType = "quobyte"
	AzureDisk             FSType = "azureDisk"
	All                   FSType = "*"
)

// AllowedFlexVolume represents a single Flexvolume that is allowed to be used.
type AllowedFlexVolume struct {
	// Driver is the name of the Flexvolume driver.
	Driver string `json:"driver" protobuf:"bytes,1,opt,name=driver"`
}

// Host Port Range defines a range of host ports that will be enabled by a policy
// for pods to use.  It requires both the start and end to be defined.
type HostPortRange struct {
	// min is the start of the range, inclusive.
	Min int32 `json:"min" protobuf:"varint,1,opt,name=min"`
	// max is the end of the range, inclusive.
	Max int32 `json:"max" protobuf:"varint,2,opt,name=max"`
}

// SELinux  Strategy Options defines the strategy type and any options used to create the strategy.
type SELinuxStrategyOptions struct {
	// type is the strategy that will dictate the allowable labels that may be set.
	Rule SELinuxStrategy `json:"rule" protobuf:"bytes,1,opt,name=rule,casttype=SELinuxStrategy"`
	// seLinuxOptions required to run as; required for MustRunAs
	// More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
	// +optional
	SELinuxOptions *v1.SELinuxOptions `json:"seLinuxOptions,omitempty" protobuf:"bytes,2,opt,name=seLinuxOptions"`
}

// SELinuxStrategy denotes strategy types for generating SELinux options for a
// Security Context.
type SELinuxStrategy string

const (
	// container must have SELinux labels of X applied.
	SELinuxStrategyMustRunAs SELinuxStrategy = "MustRunAs"
	// container may make requests for any SELinux context labels.
	SELinuxStrategyRunAsAny SELinuxStrategy = "RunAsAny"
)

// Run A sUser Strategy Options defines the strategy type and any options used to create the strategy.
type RunAsUserStrategyOptions struct {
	// Rule is the strategy that will dictate the allowable RunAsUser values that may be set.
	Rule RunAsUserStrategy `json:"rule" protobuf:"bytes,1,opt,name=rule,casttype=RunAsUserStrategy"`
	// Ranges are the allowed ranges of uids that may be used.
	// +optional
	Ranges []IDRange `json:"ranges,omitempty" protobuf:"bytes,2,rep,name=ranges"`
}

// ID Range provides a min/max of an allowed range of IDs.
type IDRange struct {
	// Min is the start of the range, inclusive.
	Min int64 `json:"min" protobuf:"varint,1,opt,name=min"`
	// Max is the end of the range, inclusive.
	Max int64 `json:"max" protobuf:"varint,2,opt,name=max"`
}

// RunAsUserStrategy denotes strategy types for generating RunAsUser values for a
// Security Context.
type RunAsUserStrategy string

const (
	// container must run as a particular uid.
	RunAsUserStrategyMustRunAs RunAsUserStrategy = "MustRunAs"
	// container must run as a non-root uid
	RunAsUserStrategyMustRunAsNonRoot RunAsUserStrategy = "MustRunAsNonRoot"
	// container may make requests for any uid.
	RunAsUserStrategyRunAsAny RunAsUserStrategy = "RunAsAny"
)

// FSGroupStrategyOptions defines the strategy type and options used to create the strategy.
type FSGroupStrategyOptions struct {
	// Rule is the strategy that will dictate what FSGroup is used in the SecurityContext.
	// +optional
	Rule FSGroupStrategyType `json:"rule,omitempty" protobuf:"bytes,1,opt,name=rule,casttype=FSGroupStrategyType"`
	// Ranges are the allowed ranges of fs groups.  If you would like to force a single
	// fs group then supply a single range with the same start and end.
	// +optional
	Ranges []IDRange `json:"ranges,omitempty" protobuf:"bytes,2,rep,name=ranges"`
}

// FSGroupStrategyType denotes strategy types for generating FSGroup values for a
// SecurityContext
type FSGroupStrategyType string

const (
	// container must have FSGroup of X applied.
	FSGroupStrategyMustRunAs FSGroupStrategyType = "MustRunAs"
	// container may make requests for any FSGroup labels.
	FSGroupStrategyRunAsAny FSGroupStrategyType = "RunAsAny"
)

// SupplementalGroupsStrategyOptions defines the strategy type and options used to create the strategy.
type SupplementalGroupsStrategyOptions struct {
	// Rule is the strategy that will dictate what supplemental groups is used in the SecurityContext.
	// +optional
	Rule SupplementalGroupsStrategyType `json:"rule,omitempty" protobuf:"bytes,1,opt,name=rule,casttype=SupplementalGroupsStrategyType"`
	// Ranges are the allowed ranges of supplemental groups.  If you would like to force a single
	// supplemental group then supply a single range with the same start and end.
	// +optional
	Ranges []IDRange `json:"ranges,omitempty" protobuf:"bytes,2,rep,name=ranges"`
}

// SupplementalGroupsStrategyType denotes strategy types for determining valid supplemental
// groups for a SecurityContext.
type SupplementalGroupsStrategyType string

const (
	// container must run as a particular gid.
	SupplementalGroupsStrategyMustRunAs SupplementalGroupsStrategyType = "MustRunAs"
	// container may make requests for any gid.
	SupplementalGroupsStrategyRunAsAny SupplementalGroupsStrategyType = "RunAsAny"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Pod Security Policy List is a list of PodSecurityPolicy objects.
type PodSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	// +optional
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items is a list of schema objects.
	Items []PodSecurityPolicy `json:"items" protobuf:"bytes,2,rep,name=items"`
}
