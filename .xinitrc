#!/usr/bin/env bash

sysresources=/etc/X11/xinit/.Xresources
userresources=$HOME/.Xresources

sysmodmap=/etc/X11/xinit/.Xmodmap
usermodmap=$HOME/.Xmodmap

# merge our X configuration
[[ -f $sysresources ]] && xrdb -merge $sysresources
[[ -f $userresources ]] && xrdb -merge $userresources

# merge modmap
[[ -f $sysmodmap ]] && xmodmap $sysmodmap
[[ -f $usermodmap ]] && xmodmap -merge $usermodmap

# start system xprofile programs
if [ -d /etc/X11/xinit/xinitrc.d ] ; then
 for f in /etc/X11/xinit/xinitrc.d/?*.sh ; do
  [ -x "$f" ] && . "$f"
 done
 unset f
fi

# start user xprofile programs
[ -f ~/.xprofile ] && . ~/.xprofile

# export DBUS
export $(dbus-launch)

# if eDP1 is connected, activate both monitors
eDP1=$(xrandr | sed -n '/eDP1 connected/p' | awk '{ print $1 }')
[[ ! -z "$eDP1" ]] && xrandr --output eDP1 --auto && sleep 3 && xrandr --output HDMI2 --auto --left-of eDP1

# export DBUS
export $(dbus-launch)

# start windows manager
exec $VMMANAGER
