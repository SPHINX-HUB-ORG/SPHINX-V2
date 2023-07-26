#$1 - tag for building the docker

build_scripts/docker_clean.sh

base_image='scapicryptobiu/libscapi_base':$1
image='scapicryptobiu/libscapi_libs:'$1
dockerfilePath='dockerfiles/DockerfileLibs'

docker pull $base_image
docker tag $base_image libscapi_base

build_scripts/rebuild_docker_image.sh $image $dockerfilePath $1
