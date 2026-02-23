runTimes=200
numPerUser=500

echo "runTimes is ${runTimes}"
echo "numsPerUser is ${numPerUser}"

make
cd bin
seq $runTimes | parallel -j 20 ./appinsertor -n $numPerUser

