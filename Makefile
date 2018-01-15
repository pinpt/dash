#
# Makefile for building all things related to this repo
#
NAME := dash
ORG := pinpt
PKG := $(ORG)/$(NAME)
PROG_NAME := $(NAME)

SHELL := /bin/bash
BASEDIR := $(shell echo $${PWD})
BUILDDIR := $(BASEDIR)/build

.PHONY: default setup clean osx linux

default: setup osx linux

setup:
	@mkdir -p $(BUILDDIR)

clean:
	@rm -rf $(BUILDDIR)

osx:
	@echo Building for OSX
	@GOOS=darwin go build -ldflags="-s -w" -o $(BUILDDIR)/dash-darwin main.go

linux:
	@echo Building for Linux
	@GOOS=linux go build -ldflags="-s -w" -o $(BUILDDIR)/dash-linux main.go
