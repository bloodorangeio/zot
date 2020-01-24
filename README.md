# zot [![Build Status](https://travis-ci.org/anuvu/zot.svg?branch=master)](https://travis-ci.org/anuvu/zot) [![codecov.io](http://codecov.io/github/anuvu/zot/coverage.svg?branch=master)](http://codecov.io/github/anuvu/zot?branch=master)

**zot** is a vendor-neutral OCI image repository server purely based on 
[OCI Distribution Specification](https://github.com/opencontainers/distribution-spec).

* Conforms to [OCI distribution spec](https://github.com/opencontainers/distribution-spec) APIs [![zot](https://github.com/bloodorangeio/oci-distribution-conformance-results/workflows/zot/badge.svg)](https://oci.bloodorange.io/results/report-zot.html) [![zot w. auth](https://github.com/bloodorangeio/oci-distribution-conformance-results/workflows/zot-auth/badge.svg)](https://oci.bloodorange.io/results/report-zot-auth.html)
* Uses [OCI storage layout](https://github.com/opencontainers/image-spec/blob/master/image-layout.md) for storage layout
* Currently suitable for on-prem deployments (e.g. colocated with Kubernetes)
* TLS support
* Authentication via TLS mutual authentication, HTTP *BASIC* (local _htpasswd_ and LDAP), and bearer auth
* Doesn't require _root_ privileges
* Swagger based documentation
* Released under Apache 2.0 License
* ```go get -u github.com/anuvu/zot/cmd/zot```


# Presentations

* [OCI Weekly Discussion - Oct 2, 2019](https://hackmd.io/El8Dd2xrTlCaCG59ns5cwg#October-2-2019)

# Build and install binary (using host's toolchain)

```
go get -u github.com/anuvu/zot/cmd/zot
```

# Full CI/CD Build

* Build inside a container (preferred)

```
make binary-container
```

* Alternatively, build inside a container using [stacker](https://github.com/anuvu/stacker) (preferred)

```
make binary-stacker
```

* Build using host's toolchain

```
make

```

Build artifacts are in bin/

# Serving
```
bin/zot serve _config-file_
```

Examples of config files are available in [examples/](examples/) dir.

# Ecosystem

Since we couldn't find clients or client libraries that are stictly compliant to
the dist spec, we had to patch containers/image (available as [anuvu/image](https://github.com/anuvu/image)) and
then link various binaries against the patched version.

## skopeo

[skopeo](https://github.com/containers/skopeo) is a tool to work with remote
image repositories.

We have a [patched version](https://github.com/anuvu/skopeo) available that
works with _zot_.

```
git clone https://github.com/anuvu/skopeo

cd skopeo

make GO111MODULE=on binary-local
```

## cri-o

[cri-o](https://github.com/cri-o/cri-o) is a OCI-based Kubernetes container
runtime interface.

We have a [patched version](https://github.com/anuvu/image) of containers/image
available that works with _zot_ which must be linked with cri-o.

```
git clone https://github.com/cri-o/cri-o

cd cri-o

echo 'replace github.com/containers/image => github.com/anuvu/image v1.5.2-0.20190827234748-f71edca6153a' >> go.mod

make bin/crio crio.conf GO111MODULE=on

```

# Caveats

* go 1.12+
* The OCI distribution spec is still WIP, and we try to keep up
