#!/bin/bash

if [ $# -eq 1 ];then
    profile=debug
else
    profile=release
fi

compare_version="9.5.0"
cur_version=`env | grep SDE_VERSION | grep -oP '\d+\.\d+\.\d+'`
#echo "$cur_version"
if [ ${cur_version} > ${compare_version} ];then
    echo "current sde version is bigger than 9.5"
    sde_version="SDE_9XX_NEW"
else
    echo "current sde version is smaller than 9.5"
    sde_version="SDE_9XX_OLD"
fi

pcitype=`lspci -d 1d1c: | grep Ethernet | grep -oP '1d1c:\d+'`
#echo "$pcitype"
typever=${pcitype#*:}
#echo "$typever"
basetype="00ff"

if [ ${typever} > ${basetype} ];then
    echo "pci type is bigger than 00ff"
    arch="tofino"
    asic="TNA_TOFINO2"
else
    echo "pci type is smaller than 00ff"
    arch="tofino2"
    asic="TNA_TOFINO"
fi

makefile="Makefile"
echo "Info: Clean first"
make -f $makefile clean
echo "Info: make the app"
make -f $makefile profile=$profile sde_version=$sde_version arch=$arch asic=$asic
echo "Info: make finished"
rm -rf 9.5.0
rm -rf 00ff
