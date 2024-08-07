REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin
BINARY_NAME?=tproxy

# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED


build:
	go build -v -o "$(OUT_DIR)/$(BINARY_NAME)" .

clean:
	rm -rf "$(OUT_DIR)/"

test:
	CGO_ENABLED=1 go test -v -race -count 1 ./...

# code linters
lint:
	hack/lint.sh

update:
	go mod tidy

# get image name from directory we're building
IMAGE_NAME=tproxy
# docker image registry, default to upstream
REGISTRY?=aojea
# tag based on date-sha
TAG?=$(shell echo "$$(date +v%Y%m%d)-$$(git describe --always --dirty)")
# the full image tag
IMAGE?=$(REGISTRY)/$(IMAGE_NAME):$(TAG)

# required to enable buildx
export DOCKER_CLI_EXPERIMENTAL=enabled
image:
# docker buildx build --platform=${PLATFORMS} $(OUTPUT) --progress=$(PROGRESS) -t ${IMAGE} --pull $(EXTRA_BUILD_OPT) .
	docker build --network host . -t ${IMAGE}

kind-image: image
	docker tag ${IMAGE} aojea/tproxy:test
	kind load docker-image aojea/tproxy:test
	kubectl delete -f install.yaml || true
	kubectl apply -f install.yaml
