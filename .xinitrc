#! /bin/bash

if [ -d /etc/X11/xinit/xinitrc.d ];then
	for f in /etc/X11/xinit/xinitrc.d/* ; do
		[ -x "$f" ] && . "$f"
	done
	unset f
fi

xrdb -merge ~/.Xresources
xset r rate 200 50

exec i3
