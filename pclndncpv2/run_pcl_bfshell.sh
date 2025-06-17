#!/bin/bash
CURPATH=$(cd `dirname $0`; pwd)

cd $SDE
./run_bfshell.sh
cd $CURPATH
