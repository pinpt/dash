<div align="center">
	<img width="500" src=".github/logo.svg" alt="pinpt-logo">
</div>

<p align="center" color="#6a737d">
	<strong>Dash is a tiny binary that runs other programs with the right environment in Kubernetes.</strong>
</p>

## Motivation

This project statisfies a simple way for running applications in a Kubernetes environment that can pull it's configuration using a 12-factor application style but with the benefit that the configuration is dynamic.

## TLDR

The `dash` binary will take one or more Kubernetes object labels (with a modified syntax) and will monitor changes to any objects matching the selector.  It will pass these values as environment variables to the passed in program (beyond the dashes) and will automatically restart them as the configuration changes.

## How it works

The `dash` binary will monitor one or more kubernetes objects (`ConfigMaps` and/or `Secrets`) and will convert the values in the object data payload into environment variables and in turn fork the command you support after the double dash with any arguments supplied.

The environment variables have a few simple formatting rules:

- Any dashes or periods are converted to underscore (e.g. `foo-bar` is `foo_bar`)
- All characters are uppercased (e.g. `foo_bar` is `FOO_BAR`)
- An optional prefix can be prepended if supplied with `--prefix`
	(e.g. `--prefix PP` and `foo-bar` is `PP_FOO_BAR`)

The environment is first inherited from the parent process (this command) and any incoming variables will take precedence.

Any parameters for configuring this command will need to proceed the double dash and any parameters after the double dash are passed along to the forked process.

```
dash c/foo=bar s/bar=foo -- mycommand foo --bar
```

The object names are expressed using a simple pattern: `<type>/<key>=<value>`
The `<type>` for ConfigMap is one of configmap, cm, m or c.
The `<type>` for Secret is one of secret, sec or s.
The `<key>=<value>` is a Kubernetes compatible object selector optionally separated by commas

For example, to find all Secrets matching the object labels `app=my-cool-secret` and `vendor=pinpoint` and all ConfigMaps matching the object labels component=agent, you would write:

```
s/app=my-cool-secret,vendor=pinpoint m/component=agent
```

The result of both items are merged together into one environment.  If multiple objects have the same variable, the behavior is undefined (meaning the order is not predictable).

All signals are sent to the forked process. However, dash will handle `SIGINT`, `SIGTERM` and `SIGQUIT` by ensuring that the forked process is shutdown within 5 seconds or will force terminate the fork and any children of the forked process.

To prevent config spam, the command will wait for a period of approximately 5 seconds of no changes before restarting the forked process. This will prevent multiple changes from causing a constant restart cycle.

The `stdout`, `stderr` and `stdin` pipes are all directly connected to the forked process.

## Docker

Add the following to your Dockerfile to install dash into your container:

```
ENV DASH_VERSION=1.0.0
RUN cd /tmp && \
	curl -O -L https://github.com/pinpt/dash/releases/download/${DASH_VERSION}/dash-linux && \
	mv /tmp/dash-linux /bin/dash && \
	chmod +x /bin/dash
```

Update `DASH_VERSION` with the version you want to use.

## License

Copyright (c) 2018 by PinPT, Inc. Licensed under the Apache Public License, v2.
