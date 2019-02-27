###############################################################################################
# TuxLite - Complete LNMP/LAMP setup script for Debian/Ubuntu                                 #
# Nginx/Apache + PHP5-FPM + MySQL                                                             #
# Stack is optimized/tuned for a 256MB server                                                 #
# Email your questions to s@tuxlite.com                                                       #
###############################################################################################

source ./options.conf

# Detect distribution. Debian or Ubuntu
DISTRO=`lsb_release -i -s`
# Distribution's release. Squeeze, wheezy, precise etc
RELEASE=`lsb_release -c -s`
if  [ $DISTRO = "" ]; then
    echo -e "\033[35;1mPlease run 'apt-get -y install lsb-release' before using this script.\033[0m"
    exit 1
fi


#### Functions Begin ####

function basic_server_setup {

    apt-get update && apt-get -y safe-upgrade

    # Reconfigure sshd - change port and disable root login
    sed -i 's/^Port [0-9]*/Port '${SSHD_PORT}'/' /etc/ssh/sshd_config
    if  [ $ROOT_LOGIN = "no" ]; then
        sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    fi;
    service ssh reload

    # Set hostname and FQDN
    sed -i 's/'${SERVER_IP}'.*/'${SERVER_IP}' '${HOSTNAME_FQDN}' '${HOSTNAME}'/' /etc/hosts
    echo "$HOSTNAME" > /etc/hostname

    if [ $DISTRO = "Debian" ]; then
        # Debian system, use hostname.sh
        service hostname.sh start
    else
        # Ubuntu system, use hostname
        service hostname start
    fi

    # Basic hardening of sysctl.conf
    sed -i 's/^#net.ipv4.conf.all.accept_source_route = 0/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf
    sed -i 's/^net.ipv4.conf.all.accept_source_route = 1/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf
    sed -i 's/^#net.ipv6.conf.all.accept_source_route = 0/net.ipv6.conf.all.accept_source_route = 0/' /etc/sysctl.conf
    sed -i 's/^net.ipv6.conf.all.accept_source_route = 1/net.ipv6.conf.all.accept_source_route = 0/' /etc/sysctl.conf
    if  [ $ROOT_LOGIN = "no" ]; then
        echo -e "\033[35;1m Root login disabled, SSH port set to $SSHD_PORT. Hostname set to $HOSTNAME and FQDN to $HOSTNAME_FQDN. \033[0m"
        echo -e "\033[35;1m Remember to create a normal user account for login or you will be locked out from your box! \033[0m"
    else
        echo -e "\033[35;1m Root login active, SSH port set to $SSHD_PORT. Hostname set to $HOSTNAME and FQDN to $HOSTNAME_FQDN. \033[0m"
    fi

} # End function basic_server_setup


function setup_apt {

    # If user enables apt option in options.conf
    if [ $CONFIGURE_APT = "yes" ]; then
        cp /etc/apt/{sources.list,sources.list.bak}

        if [ $DISTRO = "Debian" ]; then
            # Debian system, use Debian sources.list
            echo -e "\033[35;1mConfiguring APT for Debian. \033[0m"
            cat > /etc/apt/sources.list <<EOF
# Main repo
deb http://http.debian.net/debian $RELEASE main non-free contrib
deb-src http://http.debian.net/debian $RELEASE main non-free contrib
# Security
deb http://security.debian.org/ $RELEASE/updates main contrib non-free
deb-src http://security.debian.org/ $RELEASE/updates main contrib non-free

EOF
        fi # End if DISTRO = Debian


        if [ $DISTRO = "Ubuntu" ]; then
            # Ubuntu system, use Ubuntu sources.list
            echo -e "\033[35;1mConfiguring APT for Ubuntu. \033[0m"
            cat > /etc/apt/sources.list <<EOF
# Main repo
deb mirror://mirrors.ubuntu.com/mirrors.txt $RELEASE main restricted universe multiverse
deb-src mirror://mirrors.ubuntu.com/mirrors.txt $RELEASE main restricted universe multiverse

# Security & updates
deb mirror://mirrors.ubuntu.com/mirrors.txt $RELEASE-updates main restricted universe multiverse
deb-src mirror://mirrors.ubuntu.com/mirrors.txt $RELEASE-updates main restricted universe multiverse
deb mirror://mirrors.ubuntu.com/mirrors.txt $RELEASE-security main restricted universe multiverse
deb-src mirror://mirrors.ubuntu.com/mirrors.txt $RELEASE-security main restricted universe multiverse

EOF
        fi # End if DISTRO = Ubuntu


        #  Report error if detected distro is not yet supported
        if [ $DISTRO  != "Ubuntu" ] && [ $DISTRO  != "Debian" ]; then
            echo -e "\033[35;1mSorry, Distro: $DISTRO and Release: $RELEASE is not supported at this time. \033[0m"
            exit 1
        fi

    fi # End if CONFIGURE_APT = yes


    ## Third party mirrors ##

    # If user wants to install nginx from official repo and webserver=nginx
    if  [ $USE_NGINX_ORG_REPO = "yes" ] && [ $WEBSERVER = 1 ]; then
        echo -e "\033[35;1mEnabling nginx.org repo for Debian $RELEASE. \033[0m"
        cat > /etc/apt/sources.list.d/nginx.list <<EOF
# Official Nginx.org repository
deb http://nginx.org/packages/`echo $DISTRO | tr '[:upper:]' '[:lower:]'`/ $RELEASE nginx
deb-src http://nginx.org/packages/`echo $DISTRO | tr '[:upper:]' '[:lower:]'`/ $RELEASE nginx

EOF

        # Set APT pinning for Nginx package
        cat > /etc/apt/preferences.d/Nginx <<EOF
# Prevent potential conflict with main repo/dotdeb
# Always install from official nginx.org repo
Package: nginx
Pin: origin nginx.org
Pin-Priority: 1000

EOF
        wget http://nginx.org/packages/keys/nginx_signing.key
        cat nginx_signing.key | apt-key add -
    fi # End if USE_NGINX_ORG_REPO = yes && WEBSERVER = 1

    apt-get update
    echo -e "\033[35;1m Successfully configured /etc/apt/sources.list \033[0m"

} # End function setup_apt


function install_webserver {

    # From options.conf, nginx = 1, apache = 2
    if [ $WEBSERVER = 1 ]; then
        apt-get -y install nginx

        if  [ $USE_NGINX_ORG_REPO = "yes" ]; then
            mkdir /etc/nginx/sites-available
            mkdir /etc/nginx/sites-enabled

           # Disable vhost that isn't in the sites-available folder. Put a hash in front of any line.
           sed -i 's/^[^#]/#&/' /etc/nginx/conf.d/default.conf

           # Enable default vhost in /etc/nginx/sites-available
           ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
        fi

        # Add a catch-all default vhost
        cat ./config/nginx_default_vhost.conf > /etc/nginx/sites-available/default

        # Change default vhost root directory to /usr/share/nginx/html;
        sed -i 's/\(root \/usr\/share\/nginx\/\).*/\1html;/' /etc/nginx/sites-available/default

        # Create common SSL config file
        cat > /etc/nginx/ssl.conf <<EOF
ssl on;
ssl_certificate /etc/ssl/localcerts/webserver.pem;
ssl_certificate_key /etc/ssl/localcerts/webserver.key;

ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
EOF

    else
        apt-get -y install libapache2-mod-fastcgi apache2-mpm-event

        a2dismod php4
        a2dismod php5
        a2dismod fcgid
        a2enmod actions
        a2enmod fastcgi
        a2enmod ssl
        a2enmod rewrite

        cat ./config/fastcgi.conf > /etc/apache2/mods-available/fastcgi.conf

        # Create the virtual directory for the external server
        mkdir -p /srv/www/fcgi-bin.d
    fi

} # End function install_webserver


function install_extras {

    if [ $AWSTATS_ENABLE = 'yes' ]; then
        apt-get -y install awstats
    fi

    # Install any other packages specified in options.conf
    apt-get -y install $MISC_PACKAGES

} # End function install_extras


function optimize_stack {

    # If using Nginx, copy over nginx.conf
    if [ $WEBSERVER = 1 ]; then
        cat ./config/nginx.conf > /etc/nginx/nginx.conf

        # Change nginx user from  "www-data" to "nginx". Not really necessary
        # because "www-data" user is created when installing PHP5-FPM
        if  [ $USE_NGINX_ORG_REPO = "yes" ]; then
            sed -i 's/^user\s*www-data/user nginx/' /etc/nginx/nginx.conf
        fi

        # Change logrotate for nginx log files to keep 10 days worth of logs
        nginx_file=`find /etc/logrotate.d/ -maxdepth 1 -name "nginx*"`
        sed -i 's/\trotate .*/\trotate 10/' $nginx_file

    # If using Apache, copy over apache2.conf
    else
        cat ./config/apache2.conf > /etc/apache2/apache2.conf

        # Change logrotate for Apache2 log files to keep 10 days worth of logs
        sed -i 's/\tweekly/\tdaily/' /etc/logrotate.d/apache2
        sed -i 's/\trotate .*/\trotate 10/' /etc/logrotate.d/apache2

        # Remove Apache server information from headers.
        sed -i 's/ServerTokens .*/ServerTokens Prod/' /etc/apache2/conf.d/security
        sed -i 's/ServerSignature .*/ServerSignature Off/' /etc/apache2/conf.d/security

        # Add *:443 to ports.conf
        cat ./config/apache2_ports.conf > /etc/apache2/ports.conf
    fi

    if [ $AWSTATS_ENABLE = 'yes' ]; then
        # Configure AWStats
        temp=`grep -i sitedomain /etc/awstats/awstats.conf.local | wc -l`
        if [ $temp -lt 1 ]; then
            echo SiteDomain="$HOSTNAME_FQDN" >> /etc/awstats/awstats.conf.local
        fi
        # Disable Awstats from executing every 10 minutes. Put a hash in front of any line.
        sed -i 's/^[^#]/#&/' /etc/cron.d/awstats
    fi
    
    restart_webserver
    echo -e "\033[35;1m Optimize complete! \033[0m"

} # End function optimize


function check_tmp_secured {

    temp1=`grep -w "/var/tempFS /tmp ext3 loop,nosuid,noexec,rw 0 0" /etc/fstab | wc -l`
    temp2=`grep -w "tmpfs /tmp tmpfs rw,noexec,nosuid 0 0" /etc/fstab | wc -l`

    if [ $temp1  -gt 0 ] || [ $temp2 -gt 0 ]; then
        return 1
    else
        return 0
    fi

} # End function check_tmp_secured


function secure_tmp_tmpfs {

    cp /etc/fstab /etc/fstab.bak
    # Backup /tmp
    cp -Rpf /tmp /tmpbackup

    rm -rf /tmp
    mkdir /tmp

    mount -t tmpfs -o rw,noexec,nosuid tmpfs /tmp
    chmod 1777 /tmp
    echo "tmpfs /tmp tmpfs rw,noexec,nosuid 0 0" >> /etc/fstab

    # Restore /tmp
    cp -Rpf /tmpbackup/* /tmp/ >/dev/null 2>&1

    #Remove old tmp dir
    rm -rf /tmpbackup

    # Backup /var/tmp and link it to /tmp
    mv /var/tmp /var/tmpbackup
    ln -s /tmp /var/tmp

    # Copy the old data back
    cp -Rpf /var/tmpold/* /tmp/ >/dev/null 2>&1
    # Remove old tmp dir
    rm -rf /var/tmpbackup

    echo -e "\033[35;1m /tmp and /var/tmp secured using tmpfs. \033[0m"

} # End function secure_tmp_tmpfs


function secure_tmp_dd {

    cp /etc/fstab /etc/fstab.bak

    # Create 1GB space for /tmp, change count if you want smaller/larger size
    dd if=/dev/zero of=/var/tempFS bs=1024 count=$TMP_SIZE
    # Make space as a ext3 filesystem
    /sbin/mkfs.ext3 /var/tempFS

    # Backup /tmp
    cp -Rpf /tmp /tmpbackup

    # Secure /tmp
    mount -o loop,noexec,nosuid,rw /var/tempFS /tmp
    chmod 1777 /tmp
    echo "/var/tempFS /tmp ext3 loop,nosuid,noexec,rw 0 0" >> /etc/fstab

    # Restore /tmp
    cp -Rpf /tmpbackup/* /tmp/ >/dev/null 2>&1

    # Remove old tmp dir
    rm -rf /tmpbackup

    # Backup /var/tmp and link it to /tmp
    mv /var/tmp /var/tmpbackup
    ln -s /tmp /var/tmp

    # Copy the old data back
    cp -Rpf /var/tmpold/* /tmp/ >/dev/null 2>&1
    # Remove old tmp dir
    rm -rf /var/tmpbackup

    echo -e "\033[35;1m /tmp and /var/tmp secured using file created using dd. \033[0m"

} # End function secure_tmp_tmpdd


function restart_webserver {

    # From options.conf, nginx = 1, apache = 2
    if [ $WEBSERVER = 1 ]; then
        service nginx restart
    else
        apache2ctl graceful
    fi

} # End function restart_webserver



#### Main program begins ####

# Show Menu
if [ ! -n "$1" ]; then
    echo ""
    echo -e  "\033[35;1mNOTICE: Edit options.conf before using\033[0m"
    echo -e  "\033[35;1mA standard setup would be: apt + basic + install + optimize\033[0m"
    echo ""
    echo -e  "\033[35;1mSelect from the options below to use this script:- \033[0m"

    echo -n "$0"
    echo -ne "\033[36m apt\033[0m"
    echo     " - Reconfigure or reset /etc/apt/sources.list."

    echo -n  "$0"
    echo -ne "\033[36m basic\033[0m"
    echo     " - Disable root SSH logins, change SSH port and set hostname."

    echo -n "$0"
    echo -ne "\033[36m install\033[0m"
    echo     " - Installs LNMP or LAMP stack. Also installs Postfix MTA."

    echo -n "$0"
    echo -ne "\033[36m optimize\033[0m"
    echo     " - Optimizes webserver.conf, php.ini, AWStats & logrotate. Also generates self signed SSL certs."

    echo -n "$0"
    echo -ne "\033[36m dbgui\033[0m"
    echo     " - Installs or updates Adminer/phpMyAdmin."

    echo -n "$0"
    echo -ne "\033[36m tmpfs\033[0m"
    echo     " - Secures /tmp and /var/tmp using tmpfs. Not recommended for servers with less than 512MB dedicated RAM."

    echo -n "$0"
    echo -ne "\033[36m tmpdd\033[0m"
    echo     " - Secures /tmp and /var/tmp using a file created on disk. Tmp size is defined in options.conf."

    echo ""
    exit
fi
# End Show Menu


case $1 in
apt)
    setup_apt
    ;;
basic)
    basic_server_setup
    ;;
install)
    install_webserver
    restart_webserver
    echo -e "\033[35;1m Webserver + PHP-FPM + MySQL install complete! \033[0m"
    ;;
optimize)
    optimize_stack
    ;;
tmpdd)
    check_tmp_secured
    if [ $? = 0  ]; then
        secure_tmp_dd
    else
        echo -e "\033[35;1mFunction canceled. /tmp already secured. \033[0m"
    fi
    ;;
tmpfs)
    check_tmp_secured
    if [ $? = 0  ]; then
        secure_tmp_tmpfs
    else
        echo -e "\033[35;1mFunction canceled. /tmp already secured. \033[0m"
    fi
    ;;
esac


