# resoto-plugin-k8s
Kubernetes Collector Plugin for Resoto (Alpha)
!!! This plugin was created as part of a Hackathon and has not been extensively tested !!!
It is meant as a starting point for K8S work but not intended for production use.

## Usage
When the collector is enabled (`--collector k8s`) it will automatically collect the current active context if any exists.
Optionally a list of contexts to collect can be supplied using `--k8s-context contextA contextB contextC ...`.
To collect all contexts in the config file without having to specify each, use `--k8s-all-contexts`
If a config file (`--k8s-config`) is supplied it will be used instead of the default `~/.kube/config`.

Alternatively or in addition Kubernetes Clusters can be specified entirely on the commandline using e.g.
```
  --k8s-cluster mycluster \
  --k8s-apiserver https://kubernetes.docker.internal:6443 \
  --k8s-token eyJhbGciOiJSUzI1NiIsImtpZ... \
  --k8s-cacert /path/to/ca.crt
```

Multiple clusters can be specified in which case the corresponding apiserver, token and cacert options must also be specified in the same place.

For example if `clusterC` is provided in third place using `--k8s-cluster firstcluster othercluster clusterC` then the apiserver URI, token and cacert of `clusterC` must also be provided in third place of the corresponding args.

## List of arguments
```
  --k8s-context K8S_CONTEXT [K8S_CONTEXT ...]
                        Kubernetes Context Name
  --k8s-config K8S_CONFIG
                        Kubernetes Config File
  --k8s-cluster K8S_CLUSTER [K8S_CLUSTER ...]
                        Kubernetes Cluster Name
  --k8s-apiserver K8S_APISERVER [K8S_APISERVER ...]
                        Kubernetes API server
  --k8s-token K8S_TOKEN [K8S_TOKEN ...]
                        Kubernetes Token
  --k8s-cacert K8S_CACERT [K8S_CACERT ...]
                        Kubernetes CA Certificate
  --k8s-collect K8S_COLLECT [K8S_COLLECT ...]
                        Kubernetes objects to collect (default: all)
  --k8s-no-collect K8S_NO_COLLECT [K8S_NO_COLLECT ...]
                        Kubernetes objects not to collect
  --k8s-pool-size K8S_POOL_SIZE
                        Kubernetes Thread Pool Size (default: 5)
  --k8s-fork            Kubernetes use forked process instead of threads (default: False)
  --k8s-all-contexts    Kubernetes collect all contexts in kubeconfig file without needed to specify --k8s-context (default: False)
```
