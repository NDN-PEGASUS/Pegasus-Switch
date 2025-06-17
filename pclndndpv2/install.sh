#!/bin/bash
CURPATH=`pwd`
echo $CURPATH
ROOTPATH=$CURPATH
BUILDPATH=$ROOTPATH/target

[ -z ${SDE} ] && echo "Environment variable SDE not set" && exit 1
[ -z ${SDE_INSTALL} ] && echo "Environment variable SDE_INSTALL not set" && exit 1

export SDE=${SDE}
export SDE_INSTALL=${SDE_INSTALL}

if [ -d $BUILDPATH ]; then
   cd $BUILDPATH
   make uninstall
   make install
fi
