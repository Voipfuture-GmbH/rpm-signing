#!/bin/bash

function printHelp() {
  echo "Usage: $0 [--push] <docker image prefix>"
  exit 1
}

DO_PUSH=0
PREFIX="local.invalid/"
while [ "$#" -gt 0 ]; do
  if [ "$1" == "-h" -o "$1" == "--help" -o "$1" == "-help" ] ; then
    printHelp
  fi
  if [ "$1" == "--push" ] ; then
    DO_PUSH=1
  else
    PREFIX="$1"
  fi
  shift
done

set -e -o pipefail

. ../common.sh

IMAGE_NAME="$PREFIX${IMAGE_NAME}"
FINAL_NAME="${IMAGE_NAME}:${IMAGE_VERSION}"

GIT_REF=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

echo "Building $FINAL_NAME"
( cd .. ; docker build --no-cache -f docker/Dockerfile \
    --build-arg APP_VERSION="${APP_VERSION}" \
    --build-arg GIT_REF="${GIT_REF}" \
    -t ${FINAL_NAME} . )

docker tag ${FINAL_NAME} $IMAGE_NAME:latest

if [ "$DO_PUSH" != "0" ] ; then
  docker-push.sh $PREFIX
fi

echo "Created image ${FINAL_NAME}"
