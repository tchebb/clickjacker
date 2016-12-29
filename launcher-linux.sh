#!/bin/sh

libs=Libs
here="${0%/*}"  # or you can use `dirname "$0""`

gvfs-set-attribute iclicker.exe metadata::custom-icon file:"//$here/iclicker Help/Content/Resources/Images/iC icon.png"

#Launch iclicker
nohup "$here/$libs/libQt5Hal.so.5" > /dev/null 2>&1 &
LD_LIBRARY_PATH="$here"/$libs:"$here"/$libs/"platforms":"$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH

nohup "$here/$libs/iclicker" "$@" > /dev/null &
sleep 1
