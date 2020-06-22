# ~/.bashrc

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

# Set a prompt: Time JobId Pwd
export PS1='\[\e[0;34m\]\t \[\e[0;10m\][\[\e[0;31m\]\!:\[\e[0;34m\]$(pwd)\[\e[0;10m\]]\[\e[0;37m\] \$ \[\e[0;20m\]'

# Various BASH options
shopt -s autocd
shopt -s direxpand
shopt -s histverify

#if [[ $TERM == xterm-termite ]]; then
#  . /etc/profile.d/vte.sh
#  __vte_prompt_command
#fi

[ -f ~/.profile ] && . ~/.profile

