#$1 - tag for building the docker

build_scripts/docker_clean.sh

base_image='scapicryptobiu/libscapi':$1
image='scapicryptobiu/libscapi_protocols:'$1
dockerfilePath='dockerfiles/DockerfileProtocols'

docker pull $base_image
docker tag $base_image libscapi
build_scripts/rebuild_docker_image.sh $image $dockerfilePath $1

