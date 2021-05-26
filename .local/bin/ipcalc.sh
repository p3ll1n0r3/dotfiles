#! /bin/bash

wmctrl -r :ACTIVE: -e 0,500,200,920,680

unset IPCALC
read -p 'IPCALC input:' IPCALC

ipcalc $IPCALC

read -p 'Continue....'

