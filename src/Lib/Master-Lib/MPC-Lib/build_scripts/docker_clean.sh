echo 'deleting all containers'
docker ps -a -q | xargs --no-run-if-empty docker rm -f
echo 'deleting all images'
docker images -q | xargs --no-run-if-empty docker rmi -f