# Market Analysis Agent Makefile
# This Makefile provides targets for building, creating manifests, and deploying the agent

# Variables
IMAGE_NAME ?= market-analysis-agent
IMAGE_TAG ?= latest
KIND_CLUSTER ?= kagent
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

.PHONY: kind-load
kind-load: ## Load the Docker image into kind cluster
	@echo "Loading image into kind cluster '$(KIND_CLUSTER)': $(FULL_IMAGE_NAME)"
	kind load docker-image $(FULL_IMAGE_NAME) --name $(KIND_CLUSTER)
	@echo "Image loaded into kind cluster!"

.PHONY: manifest
manifest: ## Create Kubernetes manifests
	@echo "Creating Kubernetes manifests..."
	@mkdir -p manifests
	@echo 'apiVersion: v1' > manifests/deployment.yaml
	@echo 'kind: ServiceAccount' >> manifests/deployment.yaml
	@echo 'metadata:' >> manifests/deployment.yaml
	@echo '  name: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '  labels:' >> manifests/deployment.yaml
	@echo '    app: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '---' >> manifests/deployment.yaml
	@echo 'apiVersion: apps/v1' >> manifests/deployment.yaml
	@echo 'kind: Deployment' >> manifests/deployment.yaml
	@echo 'metadata:' >> manifests/deployment.yaml
	@echo '  name: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '  labels:' >> manifests/deployment.yaml
	@echo '    app: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo 'spec:' >> manifests/deployment.yaml
	@echo '  replicas: 1' >> manifests/deployment.yaml
	@echo '  selector:' >> manifests/deployment.yaml
	@echo '    matchLabels:' >> manifests/deployment.yaml
	@echo '      app: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '  template:' >> manifests/deployment.yaml
	@echo '    metadata:' >> manifests/deployment.yaml
	@echo '      labels:' >> manifests/deployment.yaml
	@echo '        app: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '    spec:' >> manifests/deployment.yaml
	@echo '      serviceAccountName: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '      containers:' >> manifests/deployment.yaml
	@echo '      - name: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '        image: $(FULL_IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '        imagePullPolicy: Never' >> manifests/deployment.yaml
	@echo '        ports:' >> manifests/deployment.yaml
	@echo '        - containerPort: 9998' >> manifests/deployment.yaml
	@echo '        env:' >> manifests/deployment.yaml
	@bash -c 'while IFS="=" read -r key value; do if [[ "$$key" != "" && ! "$$key" =~ ^[[:space:]]*# ]]; then echo "        - name: $$key" >> manifests/deployment.yaml; echo "          value: \"$$value\"" >> manifests/deployment.yaml; fi; done < env.kube'
	@echo '---' >> manifests/deployment.yaml
	@echo 'apiVersion: v1' >> manifests/deployment.yaml
	@echo 'kind: Service' >> manifests/deployment.yaml
	@echo 'metadata:' >> manifests/deployment.yaml
	@echo '  name: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '  labels:' >> manifests/deployment.yaml
	@echo '        app: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo 'spec:' >> manifests/deployment.yaml
	@echo '  selector:' >> manifests/deployment.yaml
	@echo '        app: $(IMAGE_NAME)' >> manifests/deployment.yaml
	@echo '  ports:' >> manifests/deployment.yaml
	@echo '  - protocol: TCP' >> manifests/deployment.yaml
	@echo '    port: 80' >> manifests/deployment.yaml
	@echo '    targetPort: 9998' >> manifests/deployment.yaml
	@echo '    appProtocol: kgateway.dev/a2a' >> manifests/deployment.yaml
	@echo '  type: ClusterIP' >> manifests/deployment.yaml
	@echo "Manifests created in manifests/ directory"

.PHONY: deploy
deploy: build kind-load manifest ## Deploy to Kubernetes (automatically builds multi-arch image, loads image and creates manifests)
	@echo "Deploying $(IMAGE_NAME) to Kubernetes..."
	@if ! command -v kubectl >/dev/null 2>&1; then \
		echo "Error: kubectl is not installed or not in PATH"; \
		exit 1; \
	fi
	@if ! kubectl cluster-info >/dev/null 2>&1; then \
		echo "Error: Cannot connect to Kubernetes cluster"; \
		exit 1; \
	fi
	kubectl apply -f manifests/
	@echo "Deployment complete! Check status with: kubectl get pods -l app=$(IMAGE_NAME)"

.PHONY: clean
clean: ## Clean up generated files
	@echo "Cleaning up..."
	@rm -rf manifests/
	@echo "Cleanup complete!"

.PHONY: run-local
run-local: ## Run the agent locally using Docker
	@echo "Running $(IMAGE_NAME) locally on port 9998..."
	docker run -p 9998:9998 --env-file .env $(FULL_IMAGE_NAME)

.PHONY: logs
logs: ## Show logs from the deployed agent
	@echo "Showing logs for $(IMAGE_NAME)..."
	kubectl logs -l app=$(IMAGE_NAME) --tail=100 -f

.PHONY: status
status: ## Show status of the deployed agent
	@echo "Status of $(IMAGE_NAME) deployment:"
	kubectl get pods -l app=$(IMAGE_NAME)
	kubectl get svc -l app=$(IMAGE_NAME)
