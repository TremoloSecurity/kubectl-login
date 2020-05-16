#!/bin/bash

export VERSION="0.0.1"

rm -rf target
mkdir -p target

env GOOS=darwin GOARCH=amd64 go build -o ./target/oulogin-$VERSION-macos ./kubectl-login.go 
env GOOS=linux GOARCH=amd64 go build -o ./target/oulogin-$VERSION-linux ./kubectl-login.go
env GOOS=windows GOARCH=amd64 go build -o ./target/oulogin-$VERSION-win.exe ./kubectl-login.go