# Quick Start

## Basic usage

Analyze a Go project and produce a trust flow map:

```bash
trust-flow-analyzer analyze /path/to/your/go/project
```

This produces `trust-flow-map.md` in the current directory.

## Custom output path

```bash
trust-flow-analyzer analyze -output report.md /path/to/project
```

## Example: analyzing kube-auth-proxy

```bash
git clone https://github.com/opendatahub-io/kube-auth-proxy.git
trust-flow-analyzer analyze -output kap-report.md ./kube-auth-proxy
```

Expected output:

```
loading packages from /path/to/kube-auth-proxy...
running authflow pass...
running defaults pass...
running contract pass...
running errorprop pass...
running lifecycle pass...
synthesizing contradictions...
wrote kap-report.md

summary:
  auth flows:      3
  config defaults: 7
  contracts:       3
  error paths:     275
  lifecycles:      0
  contradictions:  1
```

## Reading the output

The trust flow map is organized into sections:

1. **Authentication Flows**: each distinct auth path with its entry point, authn/authz steps, and posture
2. **Configuration Defaults**: security-critical fields and what their empty/nil values mean
3. **Contract Violations**: callers that ignore error returns
4. **Error Propagation**: error creation points and their handling
5. **Resource Lifecycles**: K8s resource create/delete/ownership chains
6. **Assumption Contradictions**: cross-file issues where components make incompatible assumptions

See [Understanding Output](../guides/understanding-output.md) for details on each section.
