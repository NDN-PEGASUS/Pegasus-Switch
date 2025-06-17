#!/bin/bash
CURPATH=$(cd `dirname $0`; pwd)

[ -z ${SDE} ] && echo "Environment variable SDE not set" && exit 1
[ -z ${SDE_INSTALL} ] && echo "Environment variable SDE_INSTALL not set" && exit 1
export SDE=${SDE}
export SDE_INSTALL=${SDE_INSTALL}

cd $SDE
bf_kdrv_mod=`lsmod | grep bf_kdrv`
if [ -z ${bf_kdrv_mod} ]; then
    echo "loading bf_kdrv_mod..."
    bf_kdrv_mod_load $SDE_INSTALL
fi

echo "Set the env with tofino lib"
export LD_LIBRARY_PATH=/usr/local/lib/:$SDE_INSTALL/lib/:${CURPATH}/
rm -rf *.log
rm -rf zlog-cfg-cur
echo "run the pcl ndn cp app now:"
cd $CURPATH
./pclndnrouter &
