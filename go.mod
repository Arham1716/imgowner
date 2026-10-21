module github.com/Arham1716/imgowner

go 1.25.0

// v0.1.0 resolved the base image by tag at scan time. For any image whose base
// tag had moved since the build, the layer check failed, the error was
// discarded, and every base-image CVE was reported as added-os or app — blaming
// teams for vulnerabilities they do not control. Fixed in v0.2.0.
retract v0.1.0

require (
	github.com/google/go-containerregistry v0.22.1
	github.com/moby/buildkit v0.17.1
	github.com/spf13/cobra v1.10.2
	golang.org/x/sync v0.22.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/containerd/typeurl/v2 v2.2.0 // indirect
	github.com/docker/cli v29.7.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)
