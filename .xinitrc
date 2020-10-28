#!/usr/bin/env bash

# merge our X configuration
[[ -f ~/.Xresources ]] && xrdb -I$HOME ~/.Xresources

# start xprofile programs
[ -f ~/.xprofile ] && . ~/.xprofile

# if eDP1 is connected, activate both monitors
eDP1=$(xrandr | sed -n '/eDP1 connected/p' | awk '{ print $1 }')
[[ ! -z "$eDP1" ]] && xrandr --output eDP1 --auto && sleep 3 && xrandr --output HDMI2 --auto --left-of eDP1

# export DBUS
export $(dbus-launch)

# start windows manager
exec $VMMANAGER
