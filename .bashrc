# ~/.bashrc
# Unique options to bash shell

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

# prompt ex.
#
# user@host(history_id)date:$(pwd) $
#
# jsnow@archminion(512)16:55:22:/home/jsnow $ 

export PS1='\[\e[36m\]\u\[\e[33m\]@\[\e[36m\]\h(\!)\t:$(pwd)\[\e[0;37m\] \$ \[\e[0;20m\]'

# Iteration of previous prompt options
#
# PS1='[\u@\h \W]\$ '
# PS1='\[\e[0;37m\]\# \[\e[0;31m\][\[\e[0;34m\]\u@\h \w \t\[\e[0;31m\]] \$ \[\e[0;20m\]'
# PS1='\[\e[0;37m\](\#) \[\e[0;37m\]\t \[\e[0;31m\][\[\e[0;34m\]\u@\h \w\[\e[0;31m\]] \[\e[0;37m\]\$ \[\e[0;20m\]'
# PS1='\[\e[0;37m\]\D{%T %Y-%m-%d} \[\e[0;31m\][\[\e[0;34m\]$(pwd)\[\e[0;31m\]]\[\e[0;37m\]\$ \[\e[0;20m\]'
# PS1='\[\e[0;37m\]\t \[\e[0;31m\][\[\e[0;34m\]\u@\h \w\[\e[0;31m\]]\[\e[0;37m\]\$ \[\e[0;20m\]'
# PS1='\[\e[0;37m\]\t \[\e[0;31m\][\[\e[0;34m\]$(pwd)\[\e[0;31m\]]\[\e[0;37m\]\$ \[\e[0;20m\]'
# export PS1='\[\e[0;37m\]\t \[\e[0;31m\][\[\e[0;34m\]$(pwd)\[\e[0;31m\]]\[\e[0;37m\][\!] \$ \[\e[0;20m\]'
# export PS1='\[\e[0;37m\]\t \[\!:\e[0;31m\][\[\e[0;34m\]$(pwd)\[\e[0;31m\]]\[\e[0;37m\]\$ \[\e[0;20m\]'
# export PS1='\[\e[1;36m\]\u@\h \t \[\e[0;37m\][\[\e[0;33m\]\!:\[\e[1;36m\]$(pwd)\[\e[0;37m\]]\[\e[0;37m\] \$ \[\e[0;20m\]'
# export PS1='\[\e[1;36m\]\u\[\e[1;33m\]@\[\e[1;36m\]\h(\!)\t:$(pwd)\[\e[0;37m\] \$ \[\e[0;20m\]'

# Various BASH options
shopt -s autocd
shopt -s direxpand
shopt -s histverify
shopt -s dotglob

# import general profile environment variables and aliases
[ -f ~/.profile ] && . ~/.profile
