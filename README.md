# kase
Kase is a tool for provisioning containers as per the OCI runtime specification. 

## Installation
---------------

    $ git clone https://github.com/bxffour/kase
    $ cd kase/

Build
--------------

To build with default options:

    $ make build/kase

To tweak the build tags

    $ BUILDTAGS="your_tags" make build/kase

Install
---------------

To you must run the install target with root privileges if you're going with the default 
install path

    # make install/kase

To specify your own install path 

    $ INSTALLDIR=/path/to/dir make install/kase

Demo
-------
![installation](https://github.com/bxffour/kase/blob/main/extras/kase.gif)

\
Integrating kase into Docker
------------------------

To integrate into docker the kase executable must be installed into the default install 
directory if you don't plan on editing the daemon.json file. In the case where you tweaked
the install directory, edit the extras/daemon.json file as follows:

```json
{
    "default-runtime": "kase",
    "runtimes": {
        "kase": {
            "path": "/YOUR/INSTALL/DIR/kase",
            "runtimeArgs": []
        }
    }
} 
```

To add kase to the list of docker runtimes and set it as default:

    # make integrate/docker

If for some reason you have a non standard docker config directory !(/etc/docker)

    # CFGDIR=/path/to/dir make integrate/docker

Cleanup daemon.json:

    # CFGDIR=/path/to/config make cleanup/docker

Demo
-------
![docker](https://github.com/bxffour/kase/blob/main/extras/docker.gif)

## Usage
------------

Skopeo and Umoci can be used to download and unpack OCI bundles to be used with kase

    $ skopeo copy docker://alpine:latest oci:alpine:latest
    $ umoci unpack --image alpine:latest alpine-bundle --rootless

To run a container

    $ kase run -b alpine-bundle <container-id>

To create a container using bundle

    $ kase create -b alpine-bundle <container-id>

To start a container

    $ kase start <container-id>

To pause all processes in a given container

    $ kase pause <container-id>

To delete a container

    $ kase delete <container-id>

To list containers

    $ kase list

For more info on oother commands run:

    $ kase --help
    $ kase [command] --help             // for help with a specific command

# Credit

https://github.com/opencontainers/runc - My deepest thanks to the contributors and maintainers of the runc project. Studying its well documented source made me undoubtedly taught me invaluable lessons on Go, linux and systems programming. 

## other projects

https://github.com/duyanghao/sample-container-runtime

https://unixism.net/2020/06containers-the-hard-way-gocker-a-mini-docker-written-in-go/