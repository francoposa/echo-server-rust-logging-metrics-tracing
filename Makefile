GIT_VERSION 			?= $(shell git describe --abbrev=8 --tags --always --dirty)
CONTAINER_REGISTRY 		?= ghcr.io/francoposa
REPOSITORY 				?= echo-server-rust-logging-metrics-tracing
SERVICE_NAME 			?= echo-server

.PHONY: build
build:
	docker build --build-arg=GIT_VERSION=$(GIT_VERSION) -t $(CONTAINER_REGISTRY)/$(REPOSITORY)/$(SERVICE_NAME) -f ./Dockerfile .
	docker tag $(CONTAINER_REGISTRY)/$(REPOSITORY)/$(SERVICE_NAME) $(CONTAINER_REGISTRY)/$(REPOSITORY)/$(SERVICE_NAME):$(GIT_VERSION)
	docker tag $(CONTAINER_REGISTRY)/$(REPOSITORY)/$(SERVICE_NAME) $(CONTAINER_REGISTRY)/$(REPOSITORY)/$(SERVICE_NAME):latest

.PHONY: push
push: build
	docker push $(CONTAINER_REGISTRY)/$(REPOSITORY)/$(SERVICE_NAME):$(GIT_VERSION)
	docker push $(CONTAINER_REGISTRY)/$(REPOSITORY)/$(SERVICE_NAME):latest
