#$1 - image name
#$2 - docker file path
#$3 - docker tag

echo 'building image' $1 'using dockerfile' $2
docker build --no-cache -t $1 -f $2 .
rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi

echo 'pushing image to docker hub'
docker login -u scapicryptobiu -p maliciousyao
docker push $1
