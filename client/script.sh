maxId=10000
reqNum=20
pageSize=128
runGWAS=true
getFile=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
logDir="${SCRIPT_DIR}/../log/m${maxId}n${reqNum}p${pageSize}/"
echo $logDir
mkdir $logDir

make
cd bin
if $runGWAS
then
    if $getFile
    then 
        echo "run GWAS and get File"
        ./apprequester --maxId $maxId --reqNum $reqNum --pageSize $pageSize --runGWAS --getFile
    else
        echo "run GWAS"
        ./apprequester --maxId $maxId --reqNum $reqNum --pageSize $pageSize --runGWAS 
    fi
else
    if $getFile
    then
        echo "run get File"
        ./apprequester --maxId $maxId --reqNum $reqNum --pageSize $pageSize --getFile
    else
        echo "flags are false"
        ./apprequester --maxId $maxId --reqNum $reqNum --pageSize $pageSize 
    fi
fi
