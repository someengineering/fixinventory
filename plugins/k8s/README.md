# resoto-plugin-k8s
Kubernetes Collector Plugin for Resoto (Alpha)
!!! This plugin was created as part of a Hackathon and has not been extensively tested !!!
It is meant as a starting point for K8S work but not intended for production use.

## Usage
When the collector is enabled (`resotoworker.collector = [k8s]`) it will automatically collect the current active context if any exists.
Optionally a list of contexts to collect can be supplied using `resotoworker.k8s.context`.
To collect all contexts in the config file without having to specify each, use `resotoworker.k8s.all_contexts`
If a config file (`resotoworker.k8s.config`) is supplied it will be used instead of the default `~/.kube/config`.

Alternatively or in addition Kubernetes Clusters can be specified entirely e.g.
```
  resotoworker.k8s.cluster = [mycluster]
  resotoworker.k8s.apiserver = [https://kubernetes.docker.internal:6443]
  resotoworker.k8s.token = [eyJhbGciOiJSUzI1NiIsImtpZ...]
  resotoworker.k8s.cacert = [/path/to/ca.crt]
```

Multiple clusters can be specified in which case the corresponding apiserver, token and cacert options must also be specified in the same list index.

For example if `clusterC` is provided in third place then the apiserver URI, token and cacert of `clusterC` must also be provided in third place of the corresponding options.
