# ~/.bashrc

# Bash resources and configuration
# todo:
# source ~/.local/bin/git-prompt.sh

__git_branch() {
  _GITSTATUS=$(git symbolic-ref HEAD --short 2>/dev/null | sed 's/\(.*\)/(&)/')
  echo $_GITSTATUS
}

function __stat() {
    if [ $? -eq 0 ]; then
        echo -en "\033[0;32m✔ $Color_Off "
    else
        echo -en "\033[0;31m✘ $Color_Off "
    fi
}

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

# Set a prompt: Time JobId Pwd
export PS1='$(__stat)$(__git_branch)\[\e[0;34m\]\t $(hostname -s) (\[\e[0;34m\]\!) \[\e[0;33m\]$(pwd) :\[\e[0;37m\] \$ \[\e[0;20m\]'

# Various BASH options
shopt -s autocd
shopt -s direxpand
shopt -s histverify

[ -f ~/.profile ] && . ~/.profile
