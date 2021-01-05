#!/usr/bin/env bash

# Post install script for SLES  15 v.0.1-2020105
# 
# FAR FROM DONE
#
# SLES 15 questions
# - is not automatically using rsyslog, only journalctl
# - firewalld or iptables
# - chronyd / systemd-datetimectl 

# add packages
addpkg() {
    logfunc ${FUNCNAME[0]}

    logmsg "Installing packages..."
    zypper install -y \
        "bind-utils" \
        "man" \
        "rsyslog" \
        "sysstat" \
        "vim" \
        "sudo" \
        "wget" 

    zypper install -y -t pattern yast2_basis
}

# configure auditd.conf
auditdconf() {
    logfunc ${FUNCNAME[0]}

    AUDITDFILE="/etc/audit/auditd.conf"

    filesnap $AUDITDFILE

    logmsg "Configuring Auditd service"
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = SYSLOG/g' $AUDITDFILE
    sed -i 's/^disk_full_action.*/disk_full_action = SYSLOG/g' $AUDITDFILE
    sed -i 's/^disk_error_action.*/disk_error_action = SYSLOG/g' $AUDITDFILE
    sed -i 's/^num_logs.*/num_logs = 16/g' $AUDITDFILE
    sed -i 's/^max_log_file .*/max_log_file = 50/g' $AUDITDFILE

    systemctl restart auditd.service
}

# Logrotate , Compress and store daily auditd logs
auditdcronfile() {
    logfunc ${FUNCNAME[0]}

    AUDITDCRONFILE="/etc/cron.daily/auditd"

    logmsg "Creating daily logration script for Auditd"

    # Distribute script
    openssl base64 -d << _EOF_ > $AUDITDCRONFILE
IyEvYmluL2Jhc2gKZXhwb3J0IFBBVEg9L3NiaW46L2JpbjovdXNyL3NiaW46L3Vzci9iaW4KCkZP
Uk1BVD0iJVklbSVkLSVIJU0lUyIgIyBDdXN0b21pemUgdGltZXN0YW1wIGZvcm1hdCBhcyBkZXNp
cmVkLCBwZXIgYG1hbiBkYXRlYAogICAgICAgICAgICAgICAgICAjICVZJW0lZCB3aWxsIGxlYWQg
dG8gc3RhbmRhcmQgbG9ncm90YXRpb25mb3JtYXQ6IGF1ZGl0LmxvZy4yMDIwMjIyLmd6CiAgICAg
ICAgICAgICAgICAgICMgJUZfJVQgd2lsbCBsZWFkIHRvIGZpbGVzIGxpa2U6IGF1ZGl0LmxvZy4y
MDE1LTAyLTI2XzE1OjQzOjQ2CkNPTVBSRVNTPWd6aXAgICAgICMgQ2hhbmdlIHRvIGJ6aXAyIG9y
IHh6IGFzIGRlc2lyZWQKS0VFUD0xNCAgICAgICAgICAgIyBOdW1iZXIgb2YgY29tcHJlc3NlZCBs
b2cgZmlsZXMgdG8ga2VlcApST1RBVEVfVElNRT01ICAgICAjIEFtb3VudCBvZiB0aW1lIGluIHNl
Y29uZHMgdG8gd2FpdCBmb3IgYXVkaXRkIHRvIHJvdGF0ZSBpdHMgbG9ncy4gQWRqdXN0IHRoaXMg
YXMgbmVjZXNzYXJ5CgpyZW5hbWVfYW5kX2NvbXByZXNzX29sZF9sb2dzKCkgewogICAgZm9yIGZp
bGUgaW4gJChmaW5kIC92YXIvbG9nL2F1ZGl0LyAtbmFtZSAnYXVkaXQubG9nLlswLTldJyk7IGRv
CiAgICAgICAgdGltZXN0YW1wPSQobHMgLWwgLS10aW1lLXN0eWxlPSIrJHtGT1JNQVR9IiAke2Zp
bGV9IHwgYXdrICd7cHJpbnQgJDZ9JykKICAgICAgICBuZXdmaWxlPSR7ZmlsZSUuWzAtOV19LiR7
dGltZXN0YW1wfQogICAgICAgICMgT3B0aW9uYWw6IHJlbW92ZSAiLXYiIHZlcmJvc2UgZmxhZyBm
cm9tIG5leHQgMiBsaW5lcyB0byBoaWRlIG91dHB1dAogICAgICAgIG12IC12ICR7ZmlsZX0gJHtu
ZXdmaWxlfQogICAgICAgICR7Q09NUFJFU1N9IC12ICR7bmV3ZmlsZX0KICAgIGRvbmUKfQoKZGVs
ZXRlX29sZF9jb21wcmVzc2VkX2xvZ3MoKSB7CiAgICAjIE9wdGlvbmFsOiByZW1vdmUgIi12IiB2
ZXJib3NlIGZsYWcgdG8gaGlkZSBvdXRwdXQKICAgIHJtIC1yZnYgJChmaW5kIC92YXIvbG9nL2F1
ZGl0LyAtcmVnZXh0eXBlIHBvc2l4LWV4dGVuZGVkIC1yZWdleCAnLiphdWRpdFwubG9nXC4uKih4
enxnenxiejIpJCcgfCBzb3J0IC1uIHwgaGVhZCAtbiAtJHtLRUVQfSkKfQoKa2lsbCAtVVNSMSAk
KHBpZG9mIGF1ZGl0ZCkKCnNsZWVwICRST1RBVEVfVElNRQpyZW5hbWVfYW5kX2NvbXByZXNzX29s
ZF9sb2dzCmRlbGV0ZV9vbGRfY29tcHJlc3NlZF9sb2dzCgo=
_EOF_
    
    chown root:root $AUDITDCRONFILE
    chmod u+x $AUDITDCRONFILE

}


# Set Auditing Rules
auditdrules() {
    logfunc ${FUNCNAME[0]}

}


# Disable accidentily trigger at ctrl+alt+del sequence from console
disableCtrlAltDel() {
    logfunc ${FUNCNAME[0]}

    logmsg "Disabling CTRL+ALT+DEL keystroke sequence"
    ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target
}


# save-old file with current timestamp extension
filesnap() {
    logfunc ${FUNCNAME}
    NFN="$1.$RUNDATE"
    if [[ -f $1 ]] ; then 
        logmsg "Snapshot file: $1 to $NFN"
        cp $1 $NFN
    fi
}

# Persistent files for JournalD log files
journaldpersistent() {
    logfunc ${FUNCNAME}

    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal
    systemctl restart systemd-journald
    
    JOURNALDCONF="/etc/systemd/journald.conf"
    filesnap $JOURNALDCONF
    
    logmsg "Configuring Persistent Journald Storage"
    sed -i 's/.*Storage=.*/Storage=persistent/' $JOURNALDCONF
    sed -i 's/.*Compress=.*/Compress=yes/' $JOURNALDCONF
    sed -i 's/.*SystemMaxUse=.*/SystemMaxUse=2G/' $JOURNALDCONF
}

# Log Header
logfunc() {
    msg="$(date "+%H:%M:%S") :: Begin $1"
    echo -e $msg
    echo $msg >> $LOGFILE
}


# Log Mesage
logmsg() {
    msg="$(date "+%H:%M:%S") :: $1"
    echo -e $msg
    echo $msg >> $LOGFILE
}


# Configure default  logrotate values
# Keep 28 days of log and compress with gzip
logrotateConf {
    logfunc ${FUNCNAME[0]}

    LOGROTATECONF="/etc/logrotate.conf"
    
    # Change from weekly to daily rotation
    sed -i 's/^weekly$/daily/' $LOGROTATECONF

    # Keep 28 iterations of backlogs
    sed -i 's/^rotate [0-9]*/rotate 28/' $LOGROTATECONF

    # Enable compression
    sed -i 's/^[#]\?.compress$/compress/' $LOGROTATECONF

    # Add option 'dateyesterday' after 'dateext'
    sed -i '/^dateext$/a dateyesterday' $LOGROTATECONF

    # Comment XZ compression/decompression, (use default gz)
    sed 's/^\(uncompresscmd\).*/# &/' $LOGROTATECONF
    sed 's/^\(compresscmd\).*/# &/' $LOGROTATECONF
}

# Configure to logrotate customized log files names in /etc/rsyslog.conf
logrotateSyslogFiles {
    logfunc ${FUNCNAME[0]}

    LOGROTATESYSLOGCONF="/etc/logrotate.d/syslog"
    filesnap $LOGROTATESYSLOGCONF
    
    sed -i 's/^\(\/\)/# \1/g' $LOGROTATESYSLOGCONF
    sed -i 's/^\({\)/\n\# FMTIS Configuration for Logroration of syslog file\n\/var\/log\/messages\n\/var\/log\/secure\n\/var\/log\/cron\n\/var\/log\/daemon\n\/var\/log\/kern\n\/var\/log\/local\n\/var\/log\/lpr\n\/var\/log\/mail\n\/var\/log\/news\n\/var\/log\/spooler\n\/var\/log\/syslog\n\1/g' $LOGROTATESYSLOGCONF

}

# Remove packages from standard installation
removepkg() {
    logfunc ${FUNCNAME[0]}
    
    logmsg "Removing packages..."
}

# Default SLES is NOT forwarding logs to /var/log/*.logs
# All logs are in Journalctl only
# Setup rsyslog to store local logs from 
# journald and forward to remote log-server
# ansible base: https://gist.githubusercontent.com/msekletar/7ebc5329962499dd9dbab5a98c4f64ee/raw/4d02911c1ff7ef99ce5561b52bb5edb01e069d29/forward-to-syslog.yml
# journalctl to syslog : https://www.loggly.com/ultimate-guide/centralizing-with-syslog/

# rsyslog has 2 input rules
# 1) imjournal - supports structured log data - imuxsock does not
# 2) imuxsock  - nonstructured log data - less performance intensive


# Setup Journald forward logs to local rsyslog and write old style log files in /var/log
setupforwardLogs {
    logfunc ${FUNCNAME[0]}

    JOURNALDCONF="/etc/systemd/journald.conf"
    filesnap $JOURNALDCONF

    logmsg "Configuring Journald to forward to Syslog"
    sed -i 's/^[#]\?ForwardToSyslog.*/ForwardToSyslog=yes/g' $JOURNALDCONF
}

# Setup forward rsyslog logs to remote syslog server
setuprsyslogRemote {
    RSYSLOGDCONF="/etc/rsyslog.d/fmtis-remote.conf"
    filesnap $RSYSLOGDCONF
    
    logmsg "Configuring RSyslog dropin for remote syslog destination"

cat > $RSYSLOGDCONF << _EOF_
\$WorkDirectory /var/spool/rsyslog   # where to place spool files
\$ActionQueueFileName uniqName       # unique name prefix for spool files
\$ActionQueueMaxDiskSpace 1g         # 1gb space limit (use as much as possible)
\$ActionQueueSaveOnShutdown on       # save messages to disk on shutdown
\$ActionQueueType LinkedList         # run asynchronously
\$ActionResumeRetryCount -1          # infinite retries if host is down

# Remote Logging using TCP for reliable delivery
#*.* @@remote-host

_EOF_

    systemctl restart rsyslog.service
}

# Configure local rsyslog writing to log files
# Todo: logrotate the new customized log files
setupRsyslogConf {

    RSYSLOGDCONF="/etc/rsyslog.conf"
    filesnap $RSYSLOGDCONF
    logmsg "Configuring RSyslog"

    # Send a MARK (heartbeat) message every 15th minute
    sed 's/^[#]\?\$MarkMessagePeriod.*/\$MarkMessagePeriod 900/g' $RSYSLOGDCONF

    # Comment default configuration
    sed -i 's/^\(#.Emergency\)/\n\# FMTIS Configuration in \/etc\/rsyslog.d\/fmtis-rsyslog.conf\n\# Default SLES Configuration for Rsyslog commented below\n\n\#\1/g' $RSYSLOGDCONF

    sed -i 's/^\(\*\.emerg\)/# \1/g' $RSYSLOGDCONF

    sed -i 's/^[#]\?\(mail\.\)/# \1/g' $RSYSLOGDCONF
    sed -i 's/^[#]\?\(news\.\)/# \1/g' $RSYSLOGDCONF

    sed -i 's/^\(\*\.=warning;\*\.=err\)/# \1/g' $RSYSLOGDCONF

    sed -i 's/^\(\*\.crit\)/# \1/g' $RSYSLOGDCONF

    sed -i 's/^\(\*\.\*;mail\.none;news\.none\)/# \1/g' $RSYSLOGDCONF

    sed -i 's/^\(local0\)/#\1/g' $RSYSLOGDCONF
    sed -i 's/^\(local2\)/#\1/g' $RSYSLOGDCONF
    sed -i 's/^\(local4\)/#\1/g' $RSYSLOGDCONF
    sed -i 's/^\(local6\)/#\1/g' $RSYSLOGDCONF
    sed -i 's/^\(local6\)/#\1/g' $RSYSLOGDCONF

    # Create a customized /var/log/ structure
    FMTISRSYSCLOGCONF="/etc/rsyslog.d/fmtis-rsyslog.conf"
    filesnap $FMTISRSYSCLOGCONF

    cat > $FMTISRSYSCLOGCONF << _EOF_
*.emerg                 :omusrmsg:*                                 # Everybody gets emergency messages
*.info                  /var/log/messages       	                # Log all informational
*.none                  /var/log/messages                     

auth.*                  /var/log/messages

authpriv.*              /var/log/secure                             # The authpriv file has restricted access.

cron.*                  /var/log/cron                               # Log cron stuff

daemon.*                /var/log/daemon

kern.*                  /var/log/kern

local0.*                /var/log/local
local1.*                /var/log/local
local2.*                /var/log/local
local3.*                /var/log/local
local4.*                /var/log/local
local5.*                /var/log/local
local6.*                /var/log/local
local7.*                /var/log/boot        		                # Save boot messages also to boot.log

lpr.*                   /var/log/lpr

mail.*                  -/var/log/mail                              # Log all the mail messages in one place.

news.*                  /var/log/news
news.crit               /var/log/spooler                            # Save news errors of level crit and higher in a special file.

syslog.*                /var/log/syslog

user.*                  /var/log/messages

uucp.*                  /var/log/messages
uucp.crit               /var/log/spooler

_EOF_

    systemctl restart rsyslog.service
}


# Configuring SSHD server 
# CIS controls ????
# this is an example, need more investigation
sshdConfig() {
    logfunc ${FUNCNAME[0]}

    SSHDCONFIG="/etc/ssh/sshd_config"
    filesnap $SSHDCONFIG
    logger "Hardening SSHD server configuration...."

    sed -i 's/^[#]\?Protocol.*/Protocol 2/g' $SSHDCONFIG
    sed -i 's/^[#]\?LogLevel.*/LogLevel INFO/g' $SSHDCONFIG
    sed -i 's/^[#]\?X11Forwarding.*/X11Forwarding no/g' $SSHDCONFIG
    sed -i 's/^[#]\?MaxAuthTries.*/MaxAuthTries 4/g' $SSHDCONFIG
    sed -i 's/^[#]\?IgnoreRhosts.*/IgnoreRhosts yes/g' $SSHDCONFIG
    sed -i 's/^[#]\?HostbasedAuthentication.*/HostbasedAuthentication no/g' $SSHDCONFIG
    sed -i 's/^[#]\?PermitRootLogin.*/PermitRootLogin no/g' $SSHDCONFIG
    sed -i 's/^[#]\?PermitEmptyPasswords.*/PermitEmptyPasswords no/g' $SSHDCONFIG
    sed -i 's/^[#]\?PermitUserEnvironment.*/PermitUserEnvironment no/g' $SSHDCONFIG
    sed -i 's/^[#]\?ClientAliveInterval.*/ClientAliveInterval 3600/g' $SSHDCONFIG
    sed -i 's/^[#]\?ClientAliveCountMax.*/ClientAliveCountMax 0/g' $SSHDCONFIG
    sed -i 's/^[#]\?Banner.*/Banner \/etc\/issue.net/g' $SSHDCONFIG
    sed -i 's/^[#]\?UseDNS.*/UseDNS no/g' $SSHDCONFIG

# Restrict approved SSHD Ciphers and MACs
    echo 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' >> $SSHDCONFIG
    echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' >> $SSHDCONFIG

# Ensure filepermission on configuration file
    chown root:root $SSHDCONFIG
    chmod 600 $SSHDCONFIG

    systemctl restart sshd.service
}

# Enable sysstat collection
sysstatSetup() {
    logfunc ${FUNCNAME[0]}

    logmsg "Enabling Sysstat Collection with sar"

    systemctl enable --now sysstat.service
}

# Main Program starts HERE
# --------------------------------------------------------------

# set a logfile and rundate parameter
RUNDATE="$(date +%Y%m%d-%H%M%S)"
LOGFILE="/root/sles-15-install-status-$RUNDATE.log"

# Run functions
removepkg
addpkg
auditdconf
auditdcronfile
auditdrules
journaldpersistent
disableCtrlAltDel
sshdConfig
sysstatSetup
setupforwardLogs
setuprsyslogRemote
setupRsyslogConf
logrotateConf
logrotateSyslogFiles

