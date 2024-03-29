#!/bin/bash

##########################################################
########################## VARS ##########################
##########################################################

SV_VERSION="0.2"
COLOUR_RESET='\e[0m'
aCOLOUR=(

    '\e[38;5;154m'	# DietPi green	| Lines, bullets and separators
    '\e[1m'		# Bold white	| Main descriptions
    '\e[90m'	# Grey		| Credits
    '\e[91m'	# Red		| Update notifications
)
GREEN_LINE=" ${aCOLOUR[0]}─────────────────────────────────────────────────────$COLOUR_RESET"
GRAY_LINE=" ${aCOLOUR[2]}─────────────────────────────────────────────────────$COLOUR_RESET"
GREEN_BULLET=" ${aCOLOUR[0]}-$COLOUR_RESET"
GREEN_SEPARATOR="${aCOLOUR[0]}:$COLOUR_RESET"
UP_COUNT=0

##########################################################
######################## FUNCTIONS #######################
##########################################################
header() {


    if [ $UP_COUNT -ne 0 ];
    then
        UPDATES="${aCOLOUR[3]}Update(s) available"
    else
        UPDATES="${aCOLOUR[3]}System up-to date"
    fi

	echo -e "$GREEN_LINE
${aCOLOUR[1]}ServerScript v$SV_VERSION$COLOUR_RESET $GREEN_SEPARATOR $UPDATES$COLOUR_RESET
$GREEN_LINE"
}

check_root() {
    if [ "$EUID" -ne 0 ]
        then 
            echo -e "[...] Check if user is root:  \t\t ${aCOLOUR[3]} [FALSE]"${COLOUR_RESET}
            exit
    else 
            echo -e "[...] Check if user is root:  \t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}       
    fi   
}

set_hostname() {
    echo -e "$GRAY_LINE"
    read -p "Do you want to set the hostname? (y/n): " sethostname
    echo -e "$GRAY_LINE"
    if [[ $sethostname == [yY] ]];
    then
        read -p "Enter hostname as FQDN: " hostname
        echo -e "$GRAY_LINE"
        hostnamectl set-hostname $hostname
        echo -e "[...] Set hostname:  \t\t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] Set hostname:  \t\t\t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}
    fi
}

count_updates() {
    apt update >/dev/null 2>&1
    UP_COUNT=$(apt-get -s -o Debug::NoLocking=true upgrade | grep -c ^Inst)
    clear
}

check_os() {
    . /etc/os-release
    if [ "$ID" == "debian" ]
    then
        echo -e "[...] System is a Debian machine:  \t ${aCOLOUR[o]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] System is a Debian machine:  \t ${aCOLOUR[3]} [FALSE]"${COLOUR_RESET}
        exit
    fi
}

check_os_version() {
    . /etc/os-release
    if [ "$VERSION_ID" == "12" ]
    then
        echo -e "[...] Check if Debian is Version 12:  \t ${aCOLOUR[o]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] Check if Debian is Version 12:  \t ${aCOLOUR[3]} [FALSE]"${COLOUR_RESET}
        exit
    fi    
}

update_sources_list() {
    apt install -qq -y gnupg2 dirmngr apt-transport-https ca-certificates lsb-release >/dev/null 2>&1
    echo -e "$GRAY_LINE"
    read -p "Do you want to update the sources.list file? (y/n): " soucres
    echo -e "$GRAY_LINE"
    if [[ $soucres == [yY] ]];
    then
        cp /etc/apt/sources.list /etc/apt/sources.list.bak
cat << EOF > /etc/apt/soucres.list
deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware

deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware

deb http://deb.debian.org/debian/ bookworm-backports main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm-backports main contrib non-free non-free-firmware

deb http://security.debian.org/debian-security/ bookworm-security main contrib non-free non-free-firmware
deb-src http://security.debian.org/debian-security/ bookworm-security main contrib non-free non-free-firmware
EOF
        apt update > /dev/null 2>&1
        echo -e "[...] Updated sources.list file:  \t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] Updated sources.list file:  \t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}  
    fi  
}

update_system() {

    if [ $UP_COUNT -ne 0 ];
    then
        echo -e "$GRAY_LINE"
        read -p "Do you want to update the system? (y/n): " systemupdate
        echo -e "$GRAY_LINE"
        if [[ $systemupdate == [yY] ]];
        then
            apt update >/dev/null 2>&1
            apt dist-upgrade -y >/dev/null 2>&1
            apt clean >/dev/null 2>&1
            apt-get autoremove --purge -y >/dev/null 2>&1
            echo -e "[...] System up-to date:  \t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
        else
            echo -e "[...] System up-to date:  \t\t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}
        fi
    else
        echo -e "[...] System up-to date:  \t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}  
    fi
}

nala_manager() {
    echo -e "$GRAY_LINE"
    read -p "Do you want to use nala as packagemanager (instead of apt)? (y/n): " nala
    echo -e "$GRAY_LINE"

    if [[ $nala == [yY] ]];
    then
        apt install -qq -y nala > /dev/null 2>&1
        echo -e "[...] Installed nala packagemanager:  \t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] Installed nala packagemanager:  \t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}  
    fi   
}

basic_packages() {
    echo -e "$GRAY_LINE"
    read -p "Do you want to install the basic packages? (y/n): " basicpackages
    echo -e "$GRAY_LINE"

    if [[ $basicpackages == [yY] ]];
    then
        apt install -qq -y wget ca-certificates lsb-release curl git htop ufw vim-nox htop command-not-found apt-file >/dev/null 2>&1
        apt install -qq -y fail2ban apt-listchanges needrestart sudo unattended-upgrades screen rsyslog rsync net-tools >/dev/null 2>&1
        apt-file update && update-command-not-found
        /etc/cron.daily/plocate
        echo -e "[...] Installed basic packages:  \t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] Installed basic packages:  \t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}  
    fi
}

setup_timeserver() {
    systemctl restart systemd-timesyncd.service
    sed -i '/^#/d' /etc/systemd/timesyncd.conf
    sed -i '/^NTP/d' /etc/systemd/timesyncd.conf
    echo "NTP=ntp1.dismail.de ntp2.dismail.de" >> /etc/systemd/timesyncd.conf
    timedatectl set-ntp true
    echo -e "[...] Set up timeserver:  \t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
}

setup_ssh() {
    echo -e "$GRAY_LINE"
    read -p "Do you want to your public SSH Key to the server? (y/n): " addkey
    echo -e "$GRAY_LINE"

    if [[ $addkey == [yY] ]];
    then
        read -p "Enter SSH key: " sshkey
        echo -e "$GRAY_LINE"
        echo $sshkey >> /root/.ssh/authorized_keys
        /etc/cron.daily/plocate
        echo -e "[...] SSH Key added:  \t\t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] SSH Key added:  \t\t\t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}  
    fi   
}

secure_ssh() {
    echo -e "$GRAY_LINE"
    read -p "Do you want to enhance the security of SSH? (y/n): " basicpackages
    echo -e "$GRAY_LINE"
    if [[ $basicpackages == [yY] ]];
    then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat <<EOF > /etc/ssh/sshd_config
PermitRootLogin yes

Port 22

AddressFamily any
ListenAddress 0.0.0.0

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

StrictModes yes

SyslogFacility AUTH
LogLevel VERBOSE

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

LoginGraceTime 30s
MaxAuthTries 2
MaxSessions 10
MaxStartups 10:30:60

PubkeyAuthentication yes
IgnoreRhosts yes
IgnoreUserKnownHosts yes
HostbasedAuthentication no

UsePAM yes

AuthenticationMethods publickey

PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

KerberosAuthentication no
KerberosOrLocalPasswd no
KerberosTicketCleanup yes

GSSAPIAuthentication no
GSSAPICleanupCredentials yes

TCPKeepAlive no

ClientAliveInterval 300
ClientAliveCountMax 3

PermitTunnel no

AllowTcpForwarding no

AllowAgentForwarding no

GatewayPorts no

X11Forwarding no
X11UseLocalhost yes

PermitUserEnvironment no

Compression no
UseDNS no
PrintMotd no
PrintLastLog no
Banner none
DebianBanner no

RevokedKeys /etc/ssh/revoked_keys

Subsystem sftp internal-sftp -l INFO -f LOCAL6 -u 0027

Match Group sftponly
    ForceCommand internal-sftp -l INFO -f LOCAL6 -u 0027
    ChrootDirectory /home/%u
    AllowTcpForwarding no
    AllowAgentForwarding no
    PasswordAuthentication no
    PermitRootLogin no
    X11Forwarding no

EOF
        echo -e "[...] SSH security enhanced:  \t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
        echo -e "$GRAY_LINE"
        read -p "Do you want to restart the SSH service? (y/n): " sshrestart
        echo -e "$GRAY_LINE"
        if [[ $sshrestart == [yY] ]];
        then
            service ssh restart
            echo -e "[...] SSH service restarted:  \t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
        else
            echo -e "[...] SSH service restarted:  \t\t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}
        fi
    else
        echo -e "[...] SSH security enhanced:  \t\t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}  
    fi
}

setup_ufw() {
    echo -e "$GRAY_LINE"
    read -p "Do you want to setup the firewall? (y/n): " ufw
    echo -e "$GRAY_LINE"
    if [[ $ufw == [yY] ]];
    then
        ufw default deny incoming > /dev/null 2>&1
        ufw default allow outgoing > /dev/null 2>&1
        ufw logging medium > /dev/null 2>&1
        ufw allow ssh > /dev/null 2>&1
        ufw --force enable > /dev/null 2>&1
        echo -e "[...] Firewall configured:  \t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
        echo -e "$GRAY_LINE"
        read -p "Do you to see the firewall configuration? (y/n): " ufwconfig
        echo -e "$GRAY_LINE"
        if [[ $ufwconfig == [yY] ]];
        then
            ufw status verbose
            echo -e "$GRAY_LINE"
        fi
    else
        echo -e "[...] Firewall configured:  \t\t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}
    fi  
}

setup_fail2ban() {
    echo -e "$GRAY_LINE"
    read -p "Do you want to setup fail2ban? (y/n): " fail2ban
    echo -e "$GRAY_LINE"
    if [[ $fail2ban == [yY] ]];
    then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

cat << EOF > /etc/fail2ban/jail.d/sshd.local
[sshd]
enabled=true
filter=sshd
mode=normal
port=22
protocol=tcp
logpath=/var/log/auth.log
maxretry=5
bantime=-1
ignoreip = 127.0.0.0/8 ::1
EOF

cat << EOF > /etc/fail2ban/jail.d/ufw.local
[ufw]
enabled=true
filter=ufw.aggressive
action=iptables-allports
logpath=/var/log/ufw.log
maxretry=1
bantime=-1
EOF

cat << EOF > /etc/fail2ban/filter.d/ufw.aggressive.conf
[Definition]
failregex = [UFW BLOCK].+SRC=<HOST> DST
ignoreregex =
EOF
        systemctl enable fail2ban >/dev/null 2>&1
        systemctl start fail2ban >/dev/null 2>&1
        echo -e "[...] Fail2Ban configured:  \t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] Fail2Ban configured:  \t\t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}
    fi     
}

secure_os() {
    echo -e "$GRAY_LINE"
    read -p "Do you want to secure the os? (y/n): " secureos
    echo -e "$GRAY_LINE"
    if [[ $secureos == [yY] ]];
    then
        echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0" | tee -a /etc/fstab >/dev/null 2>&1
        sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2 \n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec /" /etc/pam.d/common-password
        sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/5000/1000000/g' /etc/login.defs
        sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/5000/1000000/g' /etc/login.defs
        sed -i '/PASS_MAX_DAYS/s/99999/180/g' /etc/login.defs
        sed -i '/PASS_MIN_DAYS/s/0/1/g' /etc/login.defs
        sed -i '/PASS_WARN_AGE/s/7/28/g' /etc/login.defs
        sed -i '/UMASK/s/022/027/g' /etc/login.defs
        sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/#//g' /etc/login.defs
        sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/#//g' /etc/login.defs
        echo "HRNGDEVICE=/dev/urandom" | tee -a /etc/default/rng-tools >/dev/null 2>&1
        echo "kernel.dmesg_restrict = 1" >/etc/sysctl.d/50-dmesg-restrict.conf 2>/dev/null
        echo 'fs.suid_dumpable = 0' >/etc/sysctl.d/50-kernel-restrict.conf 2>/dev/null
        echo "kernel.exec-shield = 2" >/etc/sysctl.d/50-exec-shield.conf 2>/dev/null
        echo "kernel.randomize_va_space=2" >/etc/sysctl.d/50-rand-va-space.conf 2>/dev/null
        echo "dev.tty.ldisc_autoload = 0" >/etc/sysctl.d/50-ldisc-autoload.conf 2>/dev/null
        echo "fs.protected_fifos = 2" >/etc/sysctl.d/50-protected-fifos.conf 2>/dev/null
        echo "kernel.core_uses_pid = 1" >/etc/sysctl.d/50-core-uses-pid.conf 2>/dev/null
        echo "kernel.kptr_restrict = 2" >/etc/sysctl.d/50-kptr-restrict.conf 2>/dev/null
        echo "kernel.sysrq = 0" >/etc/sysctl.d/50-sysrq.conf 2>/dev/null
        echo "kernel.unprivileged_bpf_disabled = 1" >/etc/sysctl.d/50-unprivileged-bpf.conf 2>/dev/null
        echo "kernel.yama.ptrace_scope = 1" >/etc/sysctl.d/50-ptrace-scope.conf 2>/dev/null
        echo "net.core.bpf_jit_harden = 2" >/etc/sysctl.d/50-bpf-jit-harden.conf 2>/dev/null
        # Network hardening
        echo 'net.ipv4.tcp_timestamps = 0' >/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo 'net.ipv4.tcp_syncookies = 1' >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo "net.ipv4.conf.all.accept_source_route = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo "net.ipv4.conf.all.accept_redirects = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo "net.ipv4.conf.all.log_martians = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo "net.ipv4.conf.all.rp_filter = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo "net.ipv4.conf.all.send_redirects = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo "net.ipv4.conf.default.accept_source_route = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        echo "net.ipv4.conf.default.log_martians = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
        # FS hardening
        echo "fs.protected_hardlinks = 1" >/etc/sysctl.d/50-fs-hardening.conf 2>/dev/null
        echo "fs.protected_symlinks = 1" >>/etc/sysctl.d/50-fs-hardening.conf 2>/dev/null
        sysctl -p >/dev/null 2>&1
        # Disable uncommon filesystems
        echo "install cramfs /bin/true" >/etc/modprobe.d/uncommon-fs.conf
        echo "install freevxfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        echo "install jffs2 /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        echo "install hfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        echo "install hfsplus /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        echo "install squashfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        echo "install udf /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        echo "install fat /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        echo "install vfat /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        echo "install gfs2 /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
        # Disable uncommon network protocols
        echo "install dccp /bin/true" >/etc/modprobe.d/uncommon-net.conf
        echo "install sctp /bin/true" >>/etc/modprobe.d/uncommon-net.conf
        echo "install rds /bin/true" >>/etc/modprobe.d/uncommon-net.conf
        echo "install tipc /bin/true" >>/etc/modprobe.d/uncommon-net.conf
        # Disable Firewire
        echo "install firewire-core /bin/true" >/etc/modprobe.d/firewire.conf
        echo "install firewire-ohci /bin/true" >>/etc/modprobe.d/firewire.conf
        echo "install firewire-sbp2 /bin/true" >>/etc/modprobe.d/firewire.conf
        # Disable Bluetooth
        echo "install bluetooth " >/etc/modprobe.d/bluetooth.conf
        # Disable uncommon sound drivers
        echo "install snd-usb-audio /bin/true" >/etc/modprobe.d/uncommon-sound.conf
        echo "install snd-usb-caiaq /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
        echo "install snd-usb-us122l /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
        echo "install snd-usb-usx2y /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
        echo "install snd-usb-audio /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
        # Disable uncommon input drivers
        echo "install joydev /bin/true" >/etc/modprobe.d/uncommon-input.conf
        echo "install pcspkr /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        echo "install serio_raw /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        echo "install snd-rawmidi /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        echo "install snd-seq-midi /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        echo "install snd-seq-oss /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        echo "install snd-seq /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        echo "install snd-seq-device /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        echo "install snd-timer /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        echo "install snd /bin/true" >>/etc/modprobe.d/uncommon-input.conf
        # Remove telnet
        apt-get -y --purge remove telnet nis ntpdate >/dev/null 2>&1
        chown root:root /etc/grub.conf >/dev/null 2>&1
        chown -R root:root /etc/grub.d >/dev/null 2>&1
        chmod og-rwx /etc/grub.conf >/dev/null 2>&1
        chmod og-rwx /etc/grub.conf >/dev/null 2>&1
        chmod -R og-rwx /etc/grub.d >/dev/null 2>&1
        chown root:root /boot/grub2/grub.cfg >/dev/null 2>&1
        chmod og-rwx /boot/grub2/grub.cfg >/dev/null 2>&1
        chown root:root /boot/grub/grub.cfg >/dev/null 2>&1
        chmod og-rwx /boot/grub/grub.cfg >/dev/null 2>&1
        chmod 0700 /home/* >/dev/null 2>&1
        chmod 0644 /etc/passwd
        chmod 0644 /etc/group
        chmod -R 0600 /etc/cron.hourly
        chmod -R 0600 /etc/cron.daily
        chmod -R 0600 /etc/cron.weekly
        chmod -R 0600 /etc/cron.monthly
        chmod -R 0600 /etc/cron.d
        chmod -R 0600 /etc/crontab
        chmod -R 0600 /etc/shadow
        chmod 750 /etc/sudoers.d
        chmod -R 0440 /etc/sudoers.d/*
        chmod 0600 /etc/ssh/sshd_config
        chmod 0750 /usr/bin/w
        chmod 0750 /usr/bin/who
        chmod 0700 /etc/sysctl.conf
        chmod 644 /etc/motd
        chmod 0600 /boot/System.map-* >/dev/null 2>&1
        depmod -ae >/dev/null 2>&1
        update-initramfs -u >/dev/null 2>&1

cat << EOF > /etc/apt/apt.conf.d/51custom-unattended-upgrades
// Enable the update/upgrade script (0=disable)
APT::Periodic::Enable "1";

// Do "apt-get update" automatically every n-days (0=disable)
APT::Periodic::Update-Package-Lists "1";

// Do "apt-get upgrade --download-only" every n-days (0=disable)
APT::Periodic::Download-Upgradeable-Packages "1";

// Do "apt-get autoclean" every n-days (0=disable)
APT::Periodic::AutocleanInterval "7";

// Send report mail to root
//     0:  no report             (or null string)
//     1:  progress report       (actually any string)
//     2:  + command outputs     (remove -qq, remove 2>/dev/null, add -d)
//     3:  + trace on    APT::Periodic::Verbose "2";
APT::Periodic::Unattended-Upgrade "1";

// Automatically upgrade packages from these
Unattended-Upgrade::Origins-Pattern {
      "o=Debian,a=stable";
      "o=Debian,a=stable-updates";
      "origin=Debian,codename=${distro_codename},label=Debian-Security";
};

// You can specify your own packages to NOT automatically upgrade here
Unattended-Upgrade::Package-Blacklist {
};

// Run dpkg --force-confold --configure -a if a unclean dpkg state is detected to true to ensure that updates get installed even when the system got interrupted during a previous run
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

//Perform the upgrade when the machine is running because we wont be shutting our server down often
Unattended-Upgrade::InstallOnShutdown "false";

// Send an email to this address with information about the packages upgraded.
Unattended-Upgrade::Mail "root";

// Always send an e-mail
Unattended-Upgrade::MailOnlyOnError "false";

// Remove all unused dependencies after the upgrade has finished
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Remove any new unused dependencies after the upgrade has finished
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Automatically reboot WITHOUT CONFIRMATION if the file /var/run/reboot-required is found after the upgrade.
Unattended-Upgrade::Automatic-Reboot "false";

// Automatically reboot even if users are logged in.
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF

        echo -e "[...] System secured:  \t\t\t ${aCOLOUR[0]} [TRUE]"${COLOUR_RESET}
    else
        echo -e "[...] System secured:  \t\t\t ${aCOLOUR[2]} [SKIPPED]"${COLOUR_RESET}
    fi 
}

##########################################################
########################## MAIN ##########################
##########################################################

clear
count_updates
header
check_root
check_os
check_os_version
update_sources_list
update_system
nala_manager
basic_packages
set_hostname
setup_timeserver
setup_ssh
secure_ssh
setup_ufw
setup_fail2ban
secure_os