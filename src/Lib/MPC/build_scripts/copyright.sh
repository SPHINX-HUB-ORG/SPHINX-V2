for i in $(find . -name '*.cpp' -o -name '*.hpp' -o -name '*.h') do

# or whatever other pattern...
do
    echo $i
    cat copyright.txt $i > tmp.txt
     mv -T tmp.txt $i
 
done
