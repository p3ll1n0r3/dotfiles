#!/usr/bin/env bash

# merge our X configuration
[[ -f ~/.Xresources ]] && xrdb -I$HOME ~/.Xresources

# start xprofile programs
[ -f ~/.xprofile ] && . ~/.xprofile

# export DBUS
export $(dbus-launch)

# start windows manager
exec $VMMANAGER
