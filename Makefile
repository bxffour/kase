#======================================================================================================#
# HELPERS
#======================================================================================================#

##help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.PHONY: confirm
confirm:
	@echo -n 'Are you sure you want to perform this operation? [y/N] ' && read ans && [ $${ans:-N} = y ]
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
BUILDTAGS ?= seccomp

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
	GOOS=linux CGO_ENABLED=1 go build -tags "${BUILDTAGS} netgo osusergo" -ldflags=${linker_flags} -o ./bin/kase

##install/kase: install kase to dest dir
INSTALLDIR ?= /usr/local/bin
.PHONY: install/kase
install/kase:
	@echo 'installing kase'
	install -D -m0755 ./bin/kase ${INSTALLDIR}/kase


#======================================================================================================#
# TEST
#======================================================================================================#

##integrate/docker: set kase as your default docker runtime. (for tests only)
CFGDIR ?= /etc/docker
cfgfile = daemon.json
DESTFILE = $(CFGDIR)/$(cfgfile)

.PHONY: integrate/docker
integrate/docker: check
	@echo 'copying daemon.json...'
	cp ./extras/daemon.json $(DESTFILE)
	@echo 'sending SIGHUP to dockerd'
	pkill -SIGHUP dockerd
	@echo 'restarting docker.service'
	systemctl restart docker.service

.PHONY: check
check:
ifneq ("$(wildcard $(DESTFILE))", "")
	@echo 'daemon.json file already exists. You might lose your config if you proceed'
	@echo -n 'Do you want to proceed? [y/N]' && read ans && [ $${ans:-N} = y ]
	@echo 'backing up old daemon.json'
	@mv $(DESTFILE) $(CFGDIR)/daemon.json.old
	
else
	@echo 'daemon.json does not exist. It is safe to proceed'
endif

#======================================================================================================#
# CLEAN UP
#======================================================================================================#

STRING ?= $(shell cat $(DESTFILE) | grep '\"default-runtime\"' | awk '{print $2}' | sed 's/,//')

##cleanup/kase: remove all resources. (config files and binaries)
.PHONY: cleanup/kase
cleanup/kase: confirm cleanup/docker
ifneq ("$(wildcard $(INSTALLDIR)/kase)", "")
	@echo 'removing binary'
	@rm $(INSTALLDIR)/kase
endif

##cleanup/docker: cleanup modifications made by the integrate/docker target.
.PHONY: cleanup/docker
cleanup/docker:
ifneq ("$(wildcard $(CFGDIR)/daemon.json.old)", "")
	@echo 'restoring old daemon.json file'

ifneq ("$(wildcard $(CFGDIR)/daemon.json)", "")
		@rm $(DESTFILE)
    endif
	
	@mv $(CFGDIR)/daemon.json.old $(CFGDIR)/daemon.json
else
	@echo 'no backup of daemon.json found, moving on!'
endif

ifneq ("$(wildcard $(DESTFILE))", "")
    ifneq (,$(findstring $(STRING), $(shell cat $(DESTFILE))))
	    @echo 'found previously installed daemon.json'
	    @echo -n 'Do you want to delete it? [y/N] ' && read ans && [ $${ans:-N} = y ]
	    @echo 'removing daemon.json...'
	    @rm $(DESTFILE)
endif
endif
