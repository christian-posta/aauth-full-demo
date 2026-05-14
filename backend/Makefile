# Supply Chain Backend Makefile
# Docker image build, push, and local run.

# Variables
IMAGE_NAME ?= supply-chain-backend
IMAGE_TAG ?= latest
FULL_IMAGE_NAME = $(IMAGE_NAME):$(IMAGE_TAG)
PLATFORMS ?= linux/amd64,linux/arm64

# Default target
.PHONY: help
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Build types:"
	@echo "  build               - Build multi-arch for ARM64 + AMD64 (DEFAULT)"
	@echo "  build-single       - Build for current platform only"
	@echo "  build-multiarch-push - Build and push multi-arch to registry"
	@echo "  push-to-docker     - Build multi-arch and push to Docker Hub (DEFAULT)"
	@echo "  push-to-docker-multiarch - Build and push multi-arch to Docker Hub"

.PHONY: build
build: ## Build multi-architecture Docker image (ARM64 + AMD64) - DEFAULT
	@echo "Building multi-architecture Docker image: $(FULL_IMAGE_NAME)"
	@echo "Targeting platforms: $(PLATFORMS)"
	@if ! docker buildx version >/dev/null 2>&1; then \
		echo "Error: Docker buildx is not available. Please enable buildx or upgrade Docker."; \
		exit 1; \
	fi
	docker buildx build --platform $(PLATFORMS) -t $(FULL_IMAGE_NAME) --load .
	@echo "Multi-architecture build complete!"

.PHONY: build-single
build-single: ## Build the Docker image for current platform only
	@echo "Building Docker image for current platform: $(FULL_IMAGE_NAME)"
	docker build -t $(FULL_IMAGE_NAME) .
	@echo "Single-platform build complete!"

.PHONY: build-multiarch-push
build-multiarch-push: ## Build and push multi-architecture image to registry
	@echo "Building and pushing multi-architecture Docker image: $(FULL_IMAGE_NAME)"
	@echo "Targeting platforms: $(PLATFORMS)"
	@if ! docker buildx version >/dev/null 2>&1; then \
		echo "Error: Docker buildx is not available. Please enable buildx or upgrade Docker."; \
		exit 1; \
	fi
	docker buildx build --platform $(PLATFORMS) -t $(FULL_IMAGE_NAME) --push .
	@echo "Multi-architecture build and push complete!"

.PHONY: push-to-docker
push-to-docker: build ## Build and push multi-architecture Docker image to Docker Hub - DEFAULT
	@echo "Tagging multi-architecture image for Docker Hub..."
	docker tag $(FULL_IMAGE_NAME) ceposta/$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "Pushing multi-architecture image to Docker Hub..."
	docker push ceposta/$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "Push complete! Multi-architecture image available at: ceposta/$(IMAGE_NAME):$(IMAGE_TAG)"

.PHONY: push-to-docker-multiarch
push-to-docker-multiarch: ## Build and push multi-architecture image to Docker Hub
	@echo "Building and pushing multi-architecture image to Docker Hub..."
	@echo "Targeting platforms: $(PLATFORMS)"
	@if ! docker buildx version >/dev/null 2>&1; then \
		echo "Error: Docker buildx is not available. Please enable buildx or upgrade Docker."; \
		exit 1; \
	fi
	docker buildx build --platform $(PLATFORMS) -t ceposta/$(IMAGE_NAME):$(IMAGE_TAG) --push .
	@echo "Multi-architecture push complete! Image available at: ceposta/$(IMAGE_NAME):$(IMAGE_TAG)"

.PHONY: run-local
run-local: ## Run the backend locally using Docker
	@echo "Running $(IMAGE_NAME) locally on port 8000..."
	docker run -p 8000:8000 --env-file .env $(FULL_IMAGE_NAME)
