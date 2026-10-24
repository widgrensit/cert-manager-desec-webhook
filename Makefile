GO ?= go
IMAGE ?= cert-manager-desec-webhook:dev

.PHONY: test vet build
test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

build:
	docker build -t $(IMAGE) .
