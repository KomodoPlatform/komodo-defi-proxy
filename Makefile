.SILENT:
# Containerized workflow (supporting Podman and Docker)

_IF_PODMAN := $(shell command -v podman 2> /dev/null)

define container-tool
	$(if $(_IF_PODMAN), podman, docker)
endef

IMAGE_TAG = atomicdex-gui-auth
CONTAINER_NAME = atomicdex-gui-auth

container-build:
	@echo Building production image
	$(call container-tool) build --build-arg --no-cache -t $(IMAGE_TAG) -f Containerfile

container-start:
	$(call container-tool) run --name $(CONTAINER_NAME) --network host $(IMAGE_TAG)

container-silent-start:
	$(call container-tool) run --detach --name $(CONTAINER_NAME) --network host $(IMAGE_TAG)

container-stop:
	$(call container-tool) stop --time 1 $(CONTAINER_NAME)
	$(call container-tool) rm $(CONTAINER_NAME)

container-restart:
	$(MAKE) stop-container && $(MAKE) start-container

container-logs:
	$(call container-tool) logs --follow $(CONTAINER_NAME)

.PHONY: container-*
