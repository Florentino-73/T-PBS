cd "$(dirname "$0")"
make SGX_MODE=HW SGX_PRERELEASE=0
cd bin && ./appserver --pageSize 128 --numThreads 4 --managerCap 4
