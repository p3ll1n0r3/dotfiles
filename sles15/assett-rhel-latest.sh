#
# Hardening/Tuning for CentOS 7 and RHEL 7
#


# Todo rsyslogConfig()  # rsyslog template is not working as a default template, each facility needs to be configure to use a specific template

#### BEGIN CUSTOM FUNCTIONS ####

log() {
    msg=":: Begin $1 (`date "+%H:%M:%S"`)"
    echo -e $msg
    echo $msg >> /tmp/sles-15-install-status.log
}

##
## File system##

# Resize swap
swapSize() {
    log ${FUNCNAME[0]}

    # Get total memory installed, in kilobytes
    size=`awk '/^MemTotal:/ {print $2}' /proc/meminfo`

    # Limit swap size to 16 GB
    if [ "$size" -gt "16777216" ]; then
            size=16777216
    fi

    swapoff -a &&\
    lvresize -L "$size"k root/swap &&\
    mkswap /dev/root/swap &&\
    swapon -a
}

# Bind mount /var/tmp to /tmp
bindTmp() {
    log ${FUNCNAME[0]}
    echo '/tmp                    /var/tmp                none    bind                         0 0' >> /etc/fstab
}

# Secure mount options for /dev/shm
SecureShm() {
    log ${FUNCNAME[0]}
    echo 'tmpfs                   /dev/shm                tmpfs   defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab
}



##
## Software
##

# Software to remove
removeSoftware() {
    log ${FUNCNAME[0]}

    yum -y remove \
        "alsa*" \
        btrfs-progs \
        iwl*-firmware \
        "plymouth*" \
        postfix 
}

# Software to install
installSoftware() {
    log ${FUNCNAME[0]}

    yum -y install \
        aide \
        bind-utils \
	chrony \
        device-mapper-multipath \
        dstat \
        finger \
	freeipmi \
	gdisk \
        iotop \
        lsof \
        man-pages \
	net-tools \
	psmisc \
        policycoreutils-python \
        screen \
        sos \
        strace \
        sysfsutils \
        sysstat \
        tcpdump \
        telnet \
        traceroute \
        unzip \
        vim-enhanced \
        wget \
	bind-utils
}

# Services to disable
disableServices() {
    log ${FUNCNAME[0]}

    systemctl disable rhnsd.service 
    systemctl disable firewalld.service
}


##
## Boot loader
##

# Grub config permissions
grubConfigPerm() {
    log ${FUNCNAME[0]}

    chmod og-rwx /boot/grub2/grub.cfg
    chmod og-rwx /etc/default/grub
}

# Informative boot
grubInfoBoot() {
    log ${FUNCNAME[0]}

    for i in /boot/vmlinuz-*; do
        grubby --update-kernel=$i --remove-args="rhgb quiet" 
    done

    sed -i '/^GRUB_CMDLINE_LINUX=/ s/ rhgb//g' /etc/default/grub
    sed -i '/^GRUB_CMDLINE_LINUX=/ s/ quiet//g' /etc/default/grub
}

# Audit on boot
grubAuditBoot() {
    log ${FUNCNAME[0]}

    for i in /boot/vmlinuz-*; do
        grubby --update-kernel=$i --args="audit=1";
    done

    sed -i '/^GRUB_CMDLINE_LINUX=/ s/\"$/ audit=1\"/' /etc/default/grub
}



##
## Profile
##

profile() {
    log ${FUNCNAME[0]}

    cat > /etc/profile.d/customized.sh << '_PROFILE_'
# Enable idle timeout
export TMOUT=3600

# Enable timstamps in bash history
export HISTTIMEFORMAT='%F %T '

# Set number of commands to remember in the bash command history
export HISTSIZE=10000

# Set maximum number of lines saved in the bash history file
export HISTFILESIZE=10000

# Append history rather than overwriting. Prevents history from being
# overwritten when multiple sessions were active at the same time.
shopt -s histappend

# Enable bash completion when using the man and sudo commands
complete -cf sudo
complete -cf man
_PROFILE_
}



##
## Disable ctrl-alt-delete
##

disableCtrlAltDel() {
    log ${FUNCNAME[0]}

    ln -s /dev/null /etc/systemd/system/ctrl-alt-del.target
}


##
## NTP (TODO: NTP servers are hardcoded)
##

ntpChrony() {
    log ${FUNCNAME[0]}


    yum -y install chrony
    # Comment out any pre-defined servers
    sed -i s/^server/#server/g /etc/chrony.conf

    # Remove the IPv6 listening entry
    sed -i s/'^bindcmdaddress ::1'/'#bindcmdaddress ::1'/g /etc/chrony.conf

    for i in ntp1.net.dcinf.se ntp2.net.dcinf.se; do
        echo "server 213.153.104.1 iburst" >> /etc/chrony.conf
    done
    
    # Enable and start the chronyd daemon, and make sure the ntpd daemon is disabled
    systemctl enable chronyd
    systemctl start chronyd
}



###
### SSH
###

sshConfig() {
    log ${FUNCNAME[0]}

    f="/etc/ssh/sshd_config"
    sed -i 's/^[#]\?Protocol.*/Protocol 2/g' $f
    sed -i 's/^[#]\?LogLevel.*/LogLevel INFO/g' $f
    sed -i 's/^[#]\?X11Forwarding.*/X11Forwarding no/g' $f
    sed -i 's/^[#]\?MaxAuthTries.*/MaxAuthTries 4/g' $f
    sed -i 's/^[#]\?IgnoreRhosts.*/IgnoreRhosts yes/g' $f
    sed -i 's/^[#]\?HostbasedAuthentication.*/HostbasedAuthentication no/g' $f
    sed -i 's/^[#]\?PermitRootLogin.*/PermitRootLogin no/g' $f
    sed -i 's/^[#]\?PermitEmptyPasswords.*/PermitEmptyPasswords no/g' $f
    sed -i 's/^[#]\?PermitUserEnvironment.*/PermitUserEnvironment no/g' $f
    sed -i 's/^[#]\?ClientAliveInterval.*/ClientAliveInterval 3600/g' $f
    sed -i 's/^[#]\?ClientAliveCountMax.*/ClientAliveCountMax 0/g' $f
    sed -i 's/^[#]\?Banner.*/Banner \/etc\/issue.net/g' $f
    sed -i 's/^[#]\?UseDNS.*/UseDNS no/g' $f

# Restrict approved SSHD Ciphers and MACs
    echo 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' >> $f
    echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' >> $f

# Ensure filepermission on configuration file
    chown root:root $f
    chmod 600 $f
}

#
# Set password rules
#
passwordRules() {
    log ${FUNCNAME[0]}

	sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/g' /etc/login.defs
	sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/g' /etc/login.defs
	sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/g' /etc/login.defs
	
}

#
# Set requirement rules to root user
#
rootPasswd(){
    log ${FUNCNAME[0]}

#	chage -m 1 root
#	chage -M 90 root
}

#
#  Remove insecure telnet TTY - IBM recommendation
#
removeTTYs () {
    	log ${FUNCNAME[0]}

	sed -i '/3270/d' /etc/securetty
	sed -i '/hvsi0/d' /etc/securetty
	sed -i '/hvsi1/d' /etc/securetty
	sed -i '/hvsi2/d' /etc/securetty
	sed -i '/sclp_line0/d' /etc/securetty
	sed -i '/ttysclp0/d' /etc/securetty
}


##
## Password policy
##

# Ensure that users passwords are of good quality
passwordPolicy() {
    log ${FUNCNAME[0]}

    echo 'password   required     pam_pwquality.so retry=3' >> /etc/pam.d/passwd

    pwq="/etc/security/pwquality.conf"
    echo "minlen = 12"     >> $pwq
    echo "minclass = 3"    >> $pwq
    echo "maxrepeat = 3"   >> $pwq
    echo "maxsequence = 3" >> $pwq
}

#
# Enforce Password History
#

passwordHistory() {
    log ${FUNCNAME[0]}

	if [ ! -f /etc/security/opasswd ] ; then
		touch /etc/security/opasswd
		chown root:root /etc/security/opasswd
		chmod 600 /etc/security/opasswd
	fi
	
	sed -i '/^password.*pam_pwquality.*/apassword    required      pam_pwhistory.so remember=24 use_authok' /etc/pam.d/system-auth-customized
	sed -i '/^password.*pam_pwquality.*/apassword    required      pam_pwhistory.so remember=24 use_authok' /etc/pam.d/password-auth-customized
}

modifyMountOptions(){
    log ${FUNCNAME[0]}

	cp -p /etc/fstab /etc/fstab.original
	
	sed -i '/root-home/{s/ defaults /defaults,nodev,nosuid/}' /etc/fstab
	sed -i '/root-tmp/{s/ defaults /defaults,nodev,nosuid,noexec/}' /etc/fstab
	sed -i '/root-var/{s/ defaults /defaults,nodev,nosuid/}' /etc/fstab
	sed -i '/root-log/{s/ defaults /defaults,nodev,nosuid,noexec/}' /etc/fstab
	sed -i '/root-audit/{s/ defaults /defaults,nodev,nosuid,noexec/}' /etc/fstab
	sed -i '/boot/{s/ defaults /defaults,nodev,nosuid/}' /etc/fstab

}

##
## sudo
##

# Create the custom sudoers file with only root read access
sudoCustomFile() {
    log ${FUNCNAME[0]}

    touch /etc/sudoers.d/99-customized
    chown root:root /etc/sudoers.d/99-customized
    chmod 440 /etc/sudoers.d/99-customized
}

# Setup /etc/sudoers 
setupSudoers() {
    log ${FUNCNAME[0]}

	# create ibmadmins, evryadmins, consultadmins
	
	groupadd ibmadmins
	groupadd evryadmins
	groupadd consultadmin

	echo '%ibmadmins   ALL=(ALL) ALL' >> /etc/sudoers.d/99-customized
	echo '%evryadmins   ALL=(ALL) ALL' >> /etc/sudoers.d/99-customized
	echo '%consultadmins   ALL=(ALL) ALL' >> /etc/sudoers.d/99-customized

	# remark default wheel group

	sed -i 's/^\%wheel.*/#&/' /etc/sudoers	

	# with ALL ALL=!SUDOSUO

	echo "" >> /etc/sudoers
	echo "# The following line must be the last effective line in this file." >> /etc/sudoers
	echo 'ALL ALL=!SUDOSUDO' >> /etc/sudoers

}


##
## Mail to root
##
mailToRoot() {
    log ${FUNCNAME[0]}

    # Send to /dev/null
    sed -i 's/#root:.*/root:\t\t\/dev\/null/g' /etc/aliases
}



##
## Cron
##
cronPermissions() {
    log ${FUNCNAME[0]}

    # Whitelist root to use crontab/at command. Add any additional users
    # allowed, one per line.
    echo root > /etc/cron.allow
    echo root > /etc/at.allow

    # Remove the cron.deny and at.deny files (CIS-1.1.0 6.1.10 6.1.11)
    rm -f /etc/cron.deny
    rm -f /etc/at.deny

    # Make sure only root can read the allow files (CIS-1.1.0 6.1.10 6.1.11)
    chown root:root /etc/cron.allow /etc/at.allow
    chmod og-rwx    /etc/cron.allow /etc/at.allow

    # Restrict permissions to root for the primary anacron file (CIS-1.1.0 6.1.3)
    chown root:root /etc/anacrontab
    chmod 600 /etc/anacrontab

    # Restrict permissions to root for the primary crontab file  (CIS-1.1.0 6.1.4)
    chown root:root /etc/crontab
    chmod 600 /etc/crontab

    # Restrict the permission on all system crontab directories (CIS-1.1.0 6.1.5 6.1.6 6.1.7 6.1.8 6.1.9)
    cd /etc
    chown -R root:root cron.hourly cron.daily cron.weekly cron.monthly cron.d
    chmod -R go-rwx    cron.hourly cron.daily cron.weekly cron.monthly cron.d

    # Restrict the permissions on the spool directory for user crontab files
    chown root:root /var/spool/cron
    chmod -R go-rwx /var/spool/cron
}



##
## Banner
##
populateIssue() {
    log ${FUNCNAME[0]}

    cat > /etc/issue.net << '_FIXISSUE_'
+-----------------------------------------------------------------+
| WARNING!                                                        |
|                                                                 |
| This system is for the use of authorized users only.            |
| Individuals using this computer system without authority, or in |
| excess of their authority, are subject to having all of their   |
| activities on this system monitored and recorded by system      |
| personnel.                                                      |
|                                                                 |
| In the course of monitoring individuals improperly using this   |
| system, or in the course of system maintenance, the activities  |
| of authorized users may also be monitored.                      |
|                                                                 |
| Anyone using this system expressly consents to such monitoring  |
| and is advised that if such monitoring reveals possible         |
| evidence of criminal activity, system personnel may provide the |
| evidence of such monitoring to law enforcement officials.       |
+-----------------------------------------------------------------+
_FIXISSUE_

    cp /etc/issue.net /etc/issue
}



##
## Motd
##
populateMotd() {
    log ${FUNCNAME[0]}

    cat > /etc/motd << '_FIXMOTD_'
-------------------------------------------------------------------
System: 
Environment: Production
Applications: 
-------------------------------------------------------------------
_FIXMOTD_
}







##
## Networking
##

# Network config
networkConfig() {
    log ${FUNCNAME[0]}

    cat > /etc/sysconfig/network << '_EOF_'
NETWORKING=yes
NOZEROCONF=yes
GATEWAY=
_EOF_

    cd /etc/sysconfig/network-scripts/
    i=$(ls ifcfg-en*)
    ip=$(grep ^IPADDR= $i)
    d=$(grep ^DEVICE= $i)
    p=$(grep ^PREFIX= $i)
    cat > $i << '_EOF_'
IPADDR=
PREFIX=

DEVICE=
TYPE=Ethernet
ONBOOT=yes
HOTPLUG=no
USERCTL=no
BOOTPROTO=none
NM_CONTROLLED=no
_EOF_

    sed -i "s/^DEVICE=/$d/" $i
    sed -i "s/^PREFIX=/$p/" $i
    sed -i "s/^IPADDR=/$ip/" $i
}

# Set /etc/hosts
setupEtcHosts()
{
	printf "%s\t%s\t%s\n" $(hostname -I) $(hostname -f) $(hostname -s) >> /etc/hosts
}

# Disable IPv6
disableIpv6() {
    log ${FUNCNAME[0]}

    for i in /boot/vmlinuz-*; do
        grubby --update-kernel=$i --args="ipv6.disable=1";
    done

    sed -i '/^GRUB_CMDLINE_LINUX=/ s/\"$/ ipv6.disable=1\"/' /etc/default/grub
}
    

kernelNetworkConfig() {
    log ${FUNCNAME[0]}


    cat > /etc/sysctl.d/99-customized.conf << '_KERNELNETCONF_'
## Networking

# Secure IPv4 network settings

# Disable IP forwarding (CIS-1.1.0 4.1.1)
net.ipv4.ip_forward=0

# Disable source routed packet acceptance (CIS-1.1.0 4.2.1)
net.ipv4.conf.all.accept_source_route=0

# Disable ICMP redirect acceptance (CIS-1.1.0 4.2.2)
net.ipv4.conf.all.accept_redirects=0

# Disable secure ICMP redirect acceptance (CIS-1.1.0 4.2.3)
net.ipv4.conf.all.secure_redirects=0

# Log Suspicious Packets (CIS-1.1.0 4.2.4)
net.ipv4.conf.all.log_martians = 1

# Enable ignore broadcast requests (CIS-1.1.0 4.2.5)
net.ipv4.icmp_echo_ignore_broadcasts=1

# Enable bad error message protection (CIS-1.1.0 4.2.6)
net.ipv4.icmp_ignore_bogus_error_responses=1

# Enable RFC-recommended source route validation (CIS-1.1.0 4.2.7)
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Enable TCP SYN Cookies (CIS-1.1.0 4.2.8)
net.ipv4.tcp_syncookies=1

# Additional secure network settings, as described by Red Hat here:
# https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html-single/Security_Guide/index.html#sec-Disabling_Source_Routing

# Disable forwarding of IPv4 packets on all interfaces:
net.ipv4.conf.all.forwarding=0

# Disable forwarding of all multicast packets on all interfaces
net.ipv4.conf.all.mc_forwarding=0

# Disable acceptance of all IPv4 ICMP redirected packets on all interfaces
net.ipv4.conf.all.send_redirects=0

# IPv6 is disabled by default via the kernel command line. The below IPv6
# settings are present in case IPv6 is ever enabled.

# Disable IPv6 Router Advertisements (CIS-1.1.0 4.4.1.1)
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0

# Disable IPv6 Redirect Acceptance (CIS-1.1.0 4.4.1.2)
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
_KERNELNETCONF_
}



##
## Logging
##

rsyslogConfig() {
    log ${FUNCNAME[0]}

    cat > /etc/rsyslog.d/99-customized.conf << '_EOF_'
$template CustomizedTemplate,"%TIMESTAMP% <%syslogfacility-text%.%syslogseverity-text%> %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n" 

# $ActionFileDefaultTemplate CustomizedTemplate          # ERROR in CentOS 8 Stream, rsyslog do not support(?) with a Default Template, instead configure each log facility to use the template
#                                                        # This is not completely done yet in this Function

$FileCreateMode 0640

auth,user.*                     /var/log/messages;CustomizedTemplate
kern.*                          /var/log/kern.log;CustomizedTemplate
daemon.*                        /var/log/daemon.log;CustomizedTemplate
syslog.*                        /var/log/syslog;CustomizedTemplate
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.*    /var/log/other.log;CustomizedTemplate
#*.* @<log-host>
_EOF_

    for i in messages secure maillog cron spooler boot.log kern.log daemon.log syslog other.log; do
	touch /var/log/$i;
        chown root:root /var/log/$i;
        chmod og-rwx /var/log/$i;
    done

    # Remove this rule to avoid double logging for some info messages
    sed -i 's/^\(\*.info;mail.none;authpriv.none;cron.none.*\/var\/log\/messages\)/\n\# Commented as part of customization, see \/etc\/rsyslog.d\/99-customized.conf\n\#\1/g' /etc/rsyslog.conf
}

# Enable persistent logging for systemd
systemdPersistentLog() {
    log ${FUNCNAME[0]}

    mkdir /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal
    systemctl restart systemd-journald
}

# Add logfiles not previously defined to the syslog rotate file
syslogAddFiles() {
    log ${FUNCNAME[0]}

    f=/etc/logrotate.d/syslog
    # Append each logfile to the beginning of the file
    sed -i '1i /var/log/kern.log' $f
    sed -i '1i /var/log/daemon.log' $f
    sed -i '1i /var/log/syslog' $f
    sed -i '1i /var/log/other.log' $f
}

logrotateConfig() {
    log ${FUNCNAME[0]}

    f="/etc/logrotate.conf"
    # Change from weekly to daily rotation
    sed -i 's/^weekly$/daily/' $f

    # Keep 14 iterations of backlogs
    sed -i 's/^rotate [0-9]*/rotate 14/' $f

    # Enable compression
    sed -i 's/^#compress$/compress/' $f

    # Add option 'dateyesterday' after 'dateext'
    sed -i '/^dateext$/a dateyesterday' $f
}

logrotateAide() {
    log ${FUNCNAME[0]}

    f="/etc/logrotate.d/aide"
    sed -i 's/weekly/daily/g' $f
    sed -i 's/rotate.*/rotate 14/g' $f
    sed -i 's/\(minsize.*\)/\#\1/g' $f
}

sysstat() {
    log ${FUNCNAME[0]}

    # Make sysstat run every 5 instead of the default 10 minutes
    sed -i 's/^\*\/10/\*\/5/g' /etc/cron.d/sysstat

    # Keep logs for 14 days
    sed -i 's/^HISTORY=.*/HISTORY=14/g' /etc/sysconfig/sysstat
}


defaultUmask() {
    log ${FUNCNAME[0]}

    cp -p /etc/bashrc /etc/bashrc.original
    cp -p /etc/profile /etc/profile.original

    sed -i 's/umask 022/umask 077/' /etc/bashrc
    sed -i 's/umask 002/umask 077/' /etc/bashrc

    sed -i 's/umask 022/umask 077/' /etc/profile
    sed -i 's/umask 002/umask 077/' /etc/profile
}

lockoutLogin() {
    log ${FUNCNAME[0]}

# 
# Option 1 seems only to work on RHEL7
#
#	cp /etc/pam.d/password-auth /etc/password-auth.original
#	sed -i '/^auth.*required.*pam_env.so/aauth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=300' /etc/pam.d/password-auth
#	sed -i '/^auth.*sufficient.*pam_unix.so/aauth       [default=die]  pam_faillock.so authfail audit deny=5\nauth   sufficient    pam_faillock.so authsucc audit deny=5' /etc/pam.d/password-auth
#	sed -i 's/^account.*required.*pam_unix.so/account     required      pam_faillock.so\n&/' /etc/pam.d/password-auth

# Option 2 
	cp /etc/pam.d/password-auth-customized /etc/password-auth.original
	cp /etc/pam.d/system-auth-customized /etc/system-auth.original

	sed -i '/^auth.*required.*pam_env.so/aauth    required  pam_tally2.so deny=5 onerr=fail unlock_time=300' /etc/pam.d/password-auth-customized
	sed -i '/^auth.*required.*pam_env.so/aauth    required  pam_tally2.so deny=5 onerr=fail unlock_time=300' /etc/pam.d/system-auth-customized

	sed -i '/^account.*required.*pam_unix.so/aaccount    required  pam_tally2.so' /etc/pam.d/password-auth-customized
	sed -i '/^account.*required.*pam_unix.so/aaccount    required  pam_tally2.so' /etc/pam.d/system-auth-customized

	sed -i '/^auth.*required.*pam_tally2.so/aauth    required  pam_listfile.so item=user sense=deny file=\/etc\/security\/deny_users.txt onerr=succeed' /etc/pam.d/password-auth-customized
	sed -i '/^auth.*required.*pam_tally2.so/aauth    required  pam_listfile.so item=user sense=deny file=\/etc\/security\/deny_users.txt onerr=succeed' /etc/pam.d/system-auth-customized

	touch /etc/security/deny_users.txt
	chmod 600 /etc/security/deny_users.txt
	chown root:root /etc/security/deny_users.txt

# Exclude the Nagios account from password expiration through SSHD

	sed -i 's/^account.*include.*password-auth/account    sufficient   pam_succeed_if.so user = nagios\n&/' /etc/pam.d/sshd

# Option 3 does not work on RHEL 7 
#	cp /etc/pam.d/password-auth /etc/password-auth.original
#	sed -i '/^auth.*required.*pam_env.so/aauth    required  file=\/var\/log\/tally.log pam_tally2.so deny=5' /etc/pam.d/password-auth
#	sed -i '/^account.*required.*pam_unix.so/aaccount    required  pam_tally2.so' /etc/pam.d/password-auth

}


##
## AUDIT
##

auditConfig() {
    log ${FUNCNAME[0]}

    f="/etc/audit/auditd.conf"

    sed -i 's/^admin_space_left_action.*/admin_space_left_action = SYSLOG/g' $f
    sed -i 's/^disk_full_action.*/disk_full_action = SYSLOG/g' $f
    sed -i 's/^disk_error_action.*/disk_error_action = SYSLOG/g' $f
    sed -i 's/^num_logs.*/num_logs = 16/g' $f
    sed -i 's/^max_log_file .*/max_log_file = 50/g' $f
}

sed -i 's/^admin_space_left_action.*/admin_space_left_action = SYSLOG/g' /etc/audit/auditd.conf
sed -i 's/^disk_full_action.*/disk_full_action = SYSLOG/g' /etc/audit/auditd.conf
sed -i 's/^disk_error_action.*/disk_error_action = SYSLOG/g' /etc/audit/auditd.conf
sed -i 's/^num_logs.*/num_logs = 16/g' /etc/audit/auditd.conf
sed -i 's/^max_log_file .*/max_log_file = 50/g' /etc/audit/auditd.conf

auditRootTTY() {
    log ${FUNCNAME[0]}
    
    unlink /etc/pam.d/system-auth
    unlink /etc/pam.d/password-auth
    cp /etc/pam.d/system-auth-ac /etc/pam.d/system-auth-customized
    cp /etc/pam.d/password-auth-ac /etc/pam.d/password-auth-customized
    ln -s /etc/pam.d/system-auth-customized /etc/pam.d/system-auth
    ln -s /etc/pam.d/password-auth-customized /etc/pam.d/password-auth

    echo 'session     required      pam_tty_audit.so disable=* enable=root' >> /etc/pam.d/system-auth-customized
    echo 'session     required      pam_tty_audit.so disable=* enable=root' >> /etc/pam.d/password-auth-customized
    echo 'session     required      pam_tty_audit.so disable=* enable=root' >> /etc/pam.d/sudo-i
}

auditRules() {
    log ${FUNCNAME[0]}

    cat > /etc/audit/rules.d/99-customized.rules << '_FIXRULES_'
# Record Events That Modify Date and Time Information (CIS-1.1.0 5.2.4):
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Record Events That Modify User/Group Information (CIS-1.1.0 5.2.5)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Record Events That Modify the System's Network Environment (CIS-1.1.0 5.2.6)
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Record Events That Modify the System's Mandatory Access Controls (CIS-1.1.0 5.2.7)
-w /etc/selinux/ -p wa -k MAC-policy

# Collect Login and Logout Events (CIS-1.1.0 5.2.8)
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Collect Session Initiation Information (CIS-1.1.0 5.2.9)
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Collect Discretionary Access Control Permission Modification Events (CIS-1.1.0 5.2.10)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Collect Unsuccessful Unauthorized Access Attempts to Files (CIS-1.1.0 5.2.11)
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Collect Use of Privileged Commands (CIS-1.1.0 5.2.12)
-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/screen -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Collect Successful File System Mounts (CIS-1.1.0 5.2.13)
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Collect File Deletion Events by User (CIS-1.1.0 5.2.14)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Collect Changes to System Administration Scope (CIS-1.1.0 5.2.15)
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# Collect System Administrator Actions (sudolog) (CIS-1.1.0 5.2.16)
-w /var/log/sudo.log -p wa -k actions

# Collect Kernel Module Loading and Unloading (CIS-1.1.0 5.2.17)
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Recod Events That Modify TTY Auditing for Root
-w /etc/pam.d/system-auth-customized -p wa -k system-locale
-w /etc/pam.d/password-auth-customized -p wa -k system-locale

# Make the Audit Configuration Immutable (CIS-1.1.0 5.2.18)
-e 2
_FIXRULES_
}


##
## AIDE
##
aide() {
    log ${FUNCNAME[0]}

    echo '/usr/sbin/aide --init && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz && /usr/sbin/aide --check & # DELETEME' >> /etc/rc.local

    echo '0 4 * * * root /usr/sbin/aide --check' >> /etc/cron.d/aide
    chown root:root /etc/cron.d/aide
    chmod -R go-rwx /etc/cron.d/aide
}

##
## CFG2HTML
##
cfg2html() {
    log ${FUNCNAME[0]}

yum -y install psmisc

RPMNAME="$myPWD/cfg2html-6.30-1.git201607081048.noarch.rpm"

if [ ! -f $RPMNAME ] ; then
	echo "Missing package for CFG2HTML"
else

	rpm -ivh $RPMNAME

cat > /etc/cfg2html.sh << '_EOF_'
	cfg2html

	for n in /usr/openv/netbackup/bp.conf /opt/tivoli/tsm/client/ba/bin/dsm.sys /etc/group; do
		if [ -f $n ] ; then cp $n /var/log/cfg2html ; fi
	done

	tar cf /var/log/cfg2html.tar /var/log/cfg2html/*
	rm -rf /var/log/cfg2html/*
_EOF_

	chmod +x /etc/cfg2html.sh

cat > /etc/logrotate.d/cfg2html << '_EOF_'
/var/log/cfg2html.tar {
	missingok
	notifempty
	compress
	daily
	create 600 root root
}
_EOF_
	echo '0 23 * * * root /etc/cfg2html.sh' >> /etc/cron.d/cfg2html
	chown root:root /etc/cfg2html.sh /etc/logrotate.d/cfg2html /etc/cron.d/cfg2html
	chmod -R go-rwx /etc/cfg2html.sh /etc/logrotate.d/cfg2html /etc/cron.d/cfg2html

	/etc/cfg2html.sh
fi

}


##
## Kernel settings
##

# Randomize virtual memory region placement
kernelRandomVirtMem() {
    log ${FUNCNAME[0]}

    f="/etc/sysctl.d/99-customized.conf"
    echo '' >> $f
    echo '# Enable randomized virtual memory region placement' >> $f
    echo 'kernel.randomize_va_space = 2' >> $f
}


##
## Disable unused kernel modules
##
disableKernelModules() {
    log ${FUNCNAME[0]}

    cat > /etc/modprobe.d/customized.conf << '_FIXMODS_'
# Uncommon network protocols
install dccp     /bin/true # (CIS-4.6.1)
install sctp     /bin/true # (CIS-4.6.2) 
install rds      /bin/true # (CIS-4.6.3)
install tipc     /bin/true # (CIS-4.6.4)

# Uncommon filesystems
install cramfs   /bin/true # (CIS-1.1.18)
install freevxfs /bin/true # (CIS-1.1.19)
install jffs2    /bin/true # (CIS-1.1.20)
install hfs      /bin/true # (CIS-1.1.21)
install hfsplus  /bin/true # (CIS-1.1.22)
install squashfs /bin/true # (CIS-1.1.23)
install udf      /bin/true # (CIS-1.1.24)

# Bluetooth
install bluetooth /bin/true
_FIXMODS_
}



##
## Disable core dumps
##
disabelCoreDumps() {
    log ${FUNCNAME[0]}

    f="/etc/security/limits.d/99-customized.conf"
    echo '#<domain>      <type>  <item>         <value>' >> $f
    echo '*              hard    core           0' >> $f

    f="/etc/sysctl.d/99-customized.conf"
    echo 'fs.suid_dumpable = 0' >> $f
}



##
## Post installation gathering scripts
##
postInstallInfoGathering() {
    log ${FUNCNAME[0]}

    echo 'bash /tmp/postInstallInfoGathering.sh && rm -f /tmp/postInstallInfoGathering.sh # DELETEME' >> /etc/rc.local

    cat > /tmp/postInstallInfoGathering.sh << '_EOF_'
hostname=$(hostname -f)
mkdir /tmp/$hostname
cd /tmp/$hostname

# Installed packages
rpm -qa > installed_packages.out &
p1=$!

# Installed packages integrity
rpm -qVa | awk '$2 != "c" { print $0}' > installed_packages_integrity.out &
p2=$!

# Installed service
systemctl list-units --type=service > installed_services.out

# Running processes
ps -efZ > running_processes.out

# Listening sockets
ss -ltun > listening_sockets.out

# AIDE database
cp /var/lib/aide/aide.db.new.gz . &
p3=$!

# System file permissions (CIS-1.1.0 9.1.1)
rpm -Va --nomtime --nosize --nomd5 --nolinkto > system_file_permissions.out &
p4=$!

# World writable files (CIS-1.1.0 9.1.10)
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002        > world_writable_files.out &
p5=$!

# Un-owned files and directories (CIS-1.1.0 9.1.11)
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls                > un-owned_files_and_directories.out &
p6=$!

# Un-grouped files and directories (CIS-1.1.0 9.1.12)
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls               > un-grouped_files_and_directories.out &
p7=$!

# SUID system executables (CIS-1.1.0 9.1.13)
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print > suid_system_executables.out &
p8=$!

# SGID system executables (CIS-1.1.0 9.1.14)
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print > sgid_system_executables.out &
p9=$!

wait $p1 $p2 $p3 $p4 $p5 $p6 $p7 $p8 $p9

# Create a tar file of the content, readable only by root. The name includes
# the server hostname and the hash of the file.
cd /tmp
tar -czf $hostname.tar.gz $hostname
chown root:root $hostname.tar.gz
chmod 400 $hostname.tar.gz
hash=$(sha256sum $hostname.tar.gz | awk '{print $1}')
mv $hostname.tar.gz /root/$hostname.$hash.tar.gz
rm -rf $hostname
_EOF_
}


nagios() {
    log ${FUNCNAME[0]}

   useradd -c "Nagios Monitoring/IBM" -m nagios

   cat > /etc/sudoers.d/80-nagios << '_EOF_'

# /etc/sudoers.d/80-nagios
nagios ALL=(root) NOPASSWD:NOEXEC: /usr/sbin/ipmi-sensors,/usr/sbin/ipmi-sel,/usr/sbin/ipmi-fru

_EOF_
}

worldwidefiles() {
# Report to console for file checks
echo "Below checks should not result in anything. Otherwise it needs to be handled/modified"
echo "--------------------------------------------"

echo "Verify that no world writable files exist..."
find / -xdev -type -f -perm -0002 2>/dev/null
echo "."

echo "Verify that all files and directories have an owner."
find / -xdev -nouser 2>/dev/null
echo "."

echo "Ensure that no SUID programs have been introduced to the system."
find / -xdev -type -f -perm -4000 2>/dev/null
echo "."

echo "Ensure that no SGID programs have been introduced to the system."
find / -xdev -type -f -perm -2000 2>/dev/null
echo "."

echo "Endo file checks"

echo "."
echo "Setting the sticky bit on world writable directories.(DISABLED FOR EVALUATION)"
echo "df --local -P | awk '{ if (NR!=1) print $6 }' | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t"

#echo "Add extra audit rules if they are not part of current audit.rules"
#find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }'

}



##
##  Customized release information
##
customReleaseFile() {
    log ${FUNCNAME[0]}

    cat > /etc/customized-release << '_FIXCUSTOM_'
RHEL installation standard version. . . . . 7.3
CIS RHEL 7 Benchmark. . . . . . . . . . . . 1.1.0
Language and keyboard . . . . . . . . . . . STANDARD
Time zone . . . . . . . . . . . . . . . . . STANDARD
File system layout. . . . . . . . . . . . . STANDARD
Bind mount /var/tmp to /tmp . . . . . . . . STANDARD
Secure mount options for /dev/shm . . . . . STANDARD
Satellite . . . . . . . . . . . . . . . . . STANDARD
Yum . . . . . . . . . . . . . . . . . . . . STANDARD
Software to remove. . . . . . . . . . . . . STANDARD
Software to install . . . . . . . . . . . . STANDARD
Services to disable . . . . . . . . . . . . STANDARD
Grub config permissions . . . . . . . . . . STANDARD
Informative boot. . . . . . . . . . . . . . STANDARD
Boot audit. . . . . . . . . . . . . . . . . STANDARD
Profile . . . . . . . . . . . . . . . . . . STANDARD
Disable ctrl-alt-delete . . . . . . . . . . STANDARD
NTP . . . . . . . . . . . . . . . . . . . . STANDARD
SSH . . . . . . . . . . . . . . . . . . . . STANDARD
Password policy . . . . . . . . . . . . . . STANDARD
Sudo. . . . . . . . . . . . . . . . . . . . STANDARD
Mail to root. . . . . . . . . . . . . . . . STANDARD
Cron. . . . . . . . . . . . . . . . . . . . STANDARD
Banner. . . . . . . . . . . . . . . . . . . STANDARD
Motd. . . . . . . . . . . . . . . . . . . . STANDARD
Hosts . . . . . . . . . . . . . . . . . . . STANDARD
General network configuration . . . . . . . STANDARD
Bonding . . . . . . . . . . . . . . . . . . STANDARD
Disable IPv6. . . . . . . . . . . . . . . . STANDARD
Kernel network configuration. . . . . . . . STANDARD
Rsyslog . . . . . . . . . . . . . . . . . . STANDARD
Systemd . . . . . . . . . . . . . . . . . . STANDARD
Logrotate . . . . . . . . . . . . . . . . . STANDARD
Sysstat . . . . . . . . . . . . . . . . . . STANDARD
Audit configuration . . . . . . . . . . . . STANDARD
Audit root TTY input. . . . . . . . . . . . STANDARD
Audit rules . . . . . . . . . . . . . . . . STANDARD
Initialize AIDE . . . . . . . . . . . . . . STANDARD
Schedule periodic execution of AIDE . . . . STANDARD
SELinux . . . . . . . . . . . . . . . . . . STANDARD
Randomize virtual memory region placement . STANDARD
Disable unused kernel modules . . . . . . . STANDARD
Disable core dumps. . . . . . . . . . . . . STANDARD
Multipath . . . . . . . . . . . . . . . . . STANDARD
SAN queue depth . . . . . . . . . . . . . . STANDARD
Post installation information gathering . . STANDARD
Customized release information. . . . . . . STANDARD
_FIXCUSTOM_
}

myPWD=$('pwd')

installSoftware
removeSoftware
swapSize
bindTmp
SecureShm
disableServices
grubConfigPerm
grubInfoBoot
grubAuditBoot
profile
disableCtrlAltDel
ntpChrony
sshConfig
passwordPolicy
sudoCustomFile
mailToRoot
cronPermissions
populateIssue
populateMotd
#networkConfig
disableIpv6
kernelNetworkConfig
rsyslogConfig
systemdPersistentLog
syslogAddFiles
logrotateConfig
logrotateAide
sysstat
auditConfig
auditRootTTY
auditRules
kernelRandomVirtMem
disableKernelModules
disabelCoreDumps
customReleaseFile
aide

removeTTYs
passwordRules
passwordHistory
defaultUmask
modifyMountOptions
lockoutLogin
rootPasswd
#cfg2html
setupSudoers
nagios
setupEtcHosts
worldwidefiles


postInstallInfoGathering

#echo "bonding/" >> /etc/modprobe.d/customized.conf
echo "chmod -x /etc/rc.d/rc.local # DELETEME" >> /etc/rc.local
echo "sed -i '/DELETEME/d' /etc/rc.local /etc/rc.d/rc.local" >> /etc/rc.local
chmod +x /etc/rc.d/rc.local

