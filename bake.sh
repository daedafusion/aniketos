#!/usr/bin/env bash

set -e

parse_version() {
  mvn org.apache.maven.plugins:maven-help-plugin:2.1.1:evaluate -Dexpression=project.version|grep -Ev '(^\[|Download\w+:)'
}

container="aniketos"

if [ -n "$NOCACHE" ]; then
  nocache_option="--no-cache=true"
else
  nocache_option=""
fi

if [ -z "$DOCKER_REPOS" ]; then
  repos="quay.io/"
fi

if [ -n "$SUDO" ]; then
  sudo="sudo "
else
  sudo=""
fi

if [ -z "$TAG" ]; then
  docker_tag=$(parse_version)
else
  docker_tag=$TAG
fi

echo "Target Repos :: ${repos}"
echo "Target Tag :: ${docker_tag}"

# Build
${sudo} docker build ${nocache_option} -t "daedafusion/$container" -f aniketos-server/Dockerfile aniketos-server

# Create tags
for repo in `echo $repos`
do
  ${sudo} docker tag "daedafusion/$container:latest" "${repo}daedafusion/$container:$docker_tag"
  ${sudo} docker tag "daedafusion/$container:latest" "${repo}daedafusion/$container:latest"
done

# Push to registry
if [ "$PUSH" == "true" ]; then
  for repo in `echo $repos`
  do
    echo "Pushing to ${repo}"
    ${sudo} docker push "${repo}daedafusion/$container:$docker_tag"
    ${sudo} docker push "${repo}daedafusion/$container:latest"
  done
fi