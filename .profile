#!/usr/bin/env sh

# Profile file. Runs on login. Environmental variables are set here.

# todo : 
# add support for fish 
# add alias for fc (both bash and fish)

# Adds `~/.local/bin` and subdirectories to $PATH
[[ -d $HOME/.local/bin/ ]] && export PATH="$PATH:$(du "$HOME/.local/bin/" | cut -f2 | tr '\n' ':' | sed 's/:*$//')"
[[ -d $HOME/python ]] && export PATH="$PATH:$HOME/python/')"

# Environment
export VMMANAGER="openbox"
export EDITOR="vim"
export BROWSER="firefox"
export READER="zathura"
export FILE="ranger"

# Alias
alias ls='ls -la --group-directories-first --color=auto'
alias 'cd..'='cd ..'
alias cp='cp -i'
alias rm='rm -i'
alias df='df -h'
alias grep='grep --color=auto'
alias xclip='xclip -selection clipboard -f | xclip -selection primary -f | xclip -selection secondary'

# Environment Paths
export SCREENSHOTS="${HOME}/screenshots/"

# Start graphical server on tty1 if not already running.
[ "$(tty)" = "/dev/tty1" ] && ! pgrep -x Xorg >/dev/null && exec startx


