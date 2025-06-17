#!/bin/bash
TIMESTAMP=`date +%Y-%m-%d_%H-%M-%S`

echo "+++++Begin+++++"
echo "time stamp is: $TIMESTAMP"

PCLNDNPID=`ps -ef | grep "./pclndnrouter" | grep -v grep | awk '{print $2}'`
echo "pclndnrouter pid is ${PCLNDNPID}"
if [ "${PCLNDNPID}" != "" ]; then
    echo "now will kill ${PCLNDNPID} for pclndnrouter"
    kill -15 ${PCLNDNPID}
else
    echo "no pif exsit"
fi

echo "+++++Finish+++++"
