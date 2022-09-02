# kase
Kase is a tool for provisioning containers as per the OCI runtime specification. 

## Installation
---------------
\
Commands
----------

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
\
Integration into Docker
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
![installation](https://github.com/bxffour/kase)

## Usage
------------

To download, unpack and run rootless container

    $ skopeo copy docker://alpine:latest oci:alpine:latest
    $ umoci unpack --image alpine:latest alpine-bundle --rootless
    $ kase run -b alpine-bundle