# $1 tag for the image

build_scripts/docker_clean.sh

image='scapicryptobiu/libscapi_base:'$1
dockerfilePath='dockerfiles/PrerequisitesDockerfie'

build_scripts/rebuild_docker_image.sh $image $dockerfilePath $1
