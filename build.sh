#!/bin/bash

export VERSION="0.0.6b1"

rm -rf target
mkdir -p target

env GOOS=darwin GOARCH=amd64 go build -o ./target/oulogin-$VERSION-macos ./kubectl-login.go 
env GOOS=linux GOARCH=amd64 go build -o ./target/oulogin-$VERSION-linux ./kubectl-login.go
env GOOS=windows GOARCH=amd64 go build -o ./target/oulogin-$VERSION-win.exe ./kubectl-login.go

mkdir target/darwin
cp ./target/oulogin-$VERSION-macos target/darwin/oulogin
chmod +x target/darwin/oulogin
cp LICENSE target/darwin/
cd target/darwin/
zip oulogin-$VERSION-macos.zip ./oulogin LICENSE
cd ../../
mv target/darwin/oulogin-$VERSION-macos.zip target/
rm -rf target/darwin

mkdir target/linux
cp ./target/oulogin-$VERSION-linux target/linux/oulogin
chmod +x target/linux/oulogin
cp LICENSE target/linux/
cd target/linux/
zip oulogin-$VERSION-linux.zip ./oulogin LICENSE
cd ../../
mv target/linux/oulogin-$VERSION-linux.zip target/
rm -rf target/linux

mkdir target/win
cp ./target/oulogin-$VERSION-win.exe target/win/oulogin.exe
cp LICENSE target/win/
cd target/win/
zip oulogin-$VERSION-win.zip ./oulogin.exe ./LICENSE
cd ../../
mv target/win/oulogin-$VERSION-win.zip target/
rm -rf target/win





export MACOS_SHA256=$(shasum -a 256 ./target/oulogin-$VERSION-macos.zip | awk '{print $1}')
export LINUX_SHA256=$(shasum -a 256 ./target/oulogin-$VERSION-linux.zip | awk '{print $1}')
export WIN_SHA256=$(shasum -a 256 ./target/oulogin-$VERSION-win.zip | awk '{print $1}')

cat oulogin.yaml | sed "s/_VERSION_/$VERSION/g" | sed "s/_MAC_SHA_/$MACOS_SHA256/g" | sed "s/_LINUX_SHA_/$LINUX_SHA256/g" | sed "s/_WIN_SHA_/$WIN_SHA256/g" > target/oulogin.yaml

aws s3 sync ./target/ s3://tremolosecurity-maven/repository/$1/



