# Copied from https://github.com/project-serum/anchor
WORKDIR=$(PWD)

ANCHOR_CLI=v0.6.0
SOLANA_CLI=v1.6.6

IMG_ORG ?= sol-vpn
IMG_VER ?= $(ANCHOR_CLI)

.PHONY: build build-shell

default:

build: Dockerfile
	@docker build --build-arg ANCHOR_CLI=$(ANCHOR_CLI) --build-arg SOLANA_CLI=$(SOLANA_CLI) . -t $(IMG_ORG):$(IMG_VER)

build-shell:
	@docker run -ti --rm --net=host \
		-v $(WORKDIR):/workdir \
		$(IMG_ORG):$(IMG_VER) bash
