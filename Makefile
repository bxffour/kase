#======================================================================================================#
# HELPERS
#======================================================================================================#

##help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'


#======================================================================================================#
# QUALITY CONTROL
#======================================================================================================#

##audit: tidy dependencies and format, vet and run tests
.PHONY: audit
audit: vendor
	@echo 'Tidying and verifying module dependencies...'
	go mod tidy
	go mod verify
	@echo 'Formatting code..'
	go fmt ./...
	@echo 'Vetting code...'
	go vet ./...
	staticcheck ./...

##vendor: tidy and vendor dependencies
.PHONY: vendor
vendor:
	@echo 'Tidying and verifying module dependencies...'
	go mod tidy
	go mod verify
	@echo 'Vendoring dependencies...'
	go mod vendor

#======================================================================================================#
# BUILD
#======================================================================================================#
project = github.com/bxffour/kase
current_time = $(shell date --iso-8601=seconds)
commit = $(shell git describe --always --dirty --tags --long)
branch = $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
suf = ""
tags ?= "seccomp netgo osusergo"

ifeq ($(branch), develop)
    suf = +dev 
endif

version = $(shell cat ./VERSION)$(suf)
linker_flags = "-s -X ${project}/cmd.version=${version} -X ${project}/cmd.buildTime=${current_time} \
			   -X ${project}/cmd.commit=${commit}"

##build/kase: build kase
.PHONY: build/kase
build/kase:
	@echo 'building kase'
	GOOS=linux CGO_ENABLED=1 go build -tags ${tags} -ldflags=${linker_flags} -o ./bin/kase

##install/kase: install kase to dest dir
DESTDIR ?= /usr/local/bin
.PHONY: install/kase
install/kase:
	@echo 'installing kase'
	install -D -m0755 ./bin/kase ${DESTDIR}/kase
