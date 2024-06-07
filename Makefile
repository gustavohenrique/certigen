.PHONY: bin proto mocks run start install setup

SHELL := /bin/bash
go := $(shell which go)

setup: install
install:
	$(go) mod tidy
	$(go) install github.com/go-task/task/v3/cmd/task@latest
	$(go) install golang.org/x/tools/cmd/goimports@latest
	$(go) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.58.1
	$(go) install go.uber.org/mock/mockgen@latest

start: run
run:
	@task start

tests:
	@task tests

lint:
	@task lint

mocks:
	@task mocks

ci:
	@task ci
