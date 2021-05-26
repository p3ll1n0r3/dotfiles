#! /bin/bash

wmctrl -r :ACTIVE: -e 0,500,200,920,680

pwgen -s -B 24

read -p 'Continue....'

