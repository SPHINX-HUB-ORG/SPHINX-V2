#check if I'm clean
git pull origin master
#change to dev branch
git checkout dev
#merge with master
git merge master
#change to master branch
git checkout master
#merge master with dev
git merge dev
#push changes
git push origin master
#change back to dev
git checkout dev
