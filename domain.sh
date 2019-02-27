#!/bin/bash
######################################################################
# TuxLite virtualhost script                                         #
# Easily add/remove domains or subdomains                            #
# Configures logrotate, AWStats and PHP5-FPM                         #
# Enables/disables public viewing of AWStats and Adminer/phpMyAdmin  #
######################################################################

source ./options.conf

# Seconds to wait before removing a domain/virtualhost
REMOVE_DOMAIN_TIMER=10

# Check domain to see if it contains invalid characters. Option = yes|no.
DOMAIN_CHECK_VALIDITY="yes"

#### First initialize some static variables ####

# Logrotate Postrotate for Nginx
# From options.conf, nginx = 1, apache = 2
if [ $WEBSERVER -eq 1 ]; then
    POSTROTATE_CMD='[ ! -f /var/run/nginx.pid ] || kill -USR1 `cat /var/run/nginx.pid`'
else
    POSTROTATE_CMD='/etc/init.d/apache2 reload > /dev/null'
fi

# Variables for AWStats/Adminer|phpMyAdmin functions
# The path to find for Adminer|phpMyAdmin and Awstats symbolic links
PUBLIC_HTML_PATH="/home/*/domains/*/public_html"
VHOST_PATH="/home/*/domains/*"

#### Functions Begin ####

function initialize_variables {

    # Initialize variables based on user input. For add/rem functions displayed by the menu
    DOMAINS_FOLDER="/home/$DOMAIN_OWNER/domains"
    DOMAIN_PATH="/home/$DOMAIN_OWNER/domains/$DOMAIN"
    GIT_PATH="/home/$DOMAIN_OWNER/repos/$DOMAIN.git"

    # From options.conf, nginx = 1, apache = 2
    if [ $WEBSERVER -eq 1 ]; then
        DOMAIN_CONFIG_PATH="/etc/nginx/sites-available/$DOMAIN"
        DOMAIN_ENABLED_PATH="/etc/nginx/sites-enabled/$DOMAIN"
    else
        DOMAIN_CONFIG_PATH="/etc/apache2/sites-available/$DOMAIN"
        DOMAIN_ENABLED_PATH="/etc/apache2/sites-enabled/$DOMAIN"
    fi

    # Name of the logrotate file
    LOGROTATE_FILE="domain-$DOMAIN"

}


function reload_webserver {

    # From options.conf, nginx = 1, apache = 2
    if [ $WEBSERVER -eq 1 ]; then
        service nginx reload
    else
        apache2ctl graceful
    fi

} # End function reload_webserver


function add_domain {

    # Create public_html and log directories for domain
    mkdir -p $DOMAIN_PATH/{logs,public_html}
    touch $DOMAIN_PATH/logs/{access.log,error.log}

    cat > $DOMAIN_PATH/public_html/index.html <<EOF
<html>
<head>
<title>Welcome to $DOMAIN</title>
</head>
<body>
<h1>Welcome to $DOMAIN</h1>
<p>This page is simply a placeholder for your domain. Place your content in the appropriate directory to see it here. </p>
<p>Please replace or delete index.html when uploading or creating your site.</p>
</body>
</html>
EOF


    # Set permissions
    chown $DOMAIN_OWNER:$DOMAIN_OWNER $DOMAINS_FOLDER
    chown -R $DOMAIN_OWNER:$DOMAIN_OWNER $DOMAIN_PATH
    # Allow execute permissions to group and other so that the webserver can serve files
    chmod 711 $DOMAINS_FOLDER
    chmod 711 $DOMAIN_PATH

    # Virtualhost entry
    # From options.conf, nginx = 1, apache = 2
    if [ $WEBSERVER -eq 1 ]; then
        # Nginx webserver. Use Nginx vHost config
        cat > $DOMAIN_CONFIG_PATH <<EOF
server {
        listen 80;
        #listen [::]:80 default ipv6only=on;

        server_name www.$DOMAIN $DOMAIN;
        root $DOMAIN_PATH/public_html;
        access_log $DOMAIN_PATH/logs/access.log;
        error_log $DOMAIN_PATH/logs/error.log;

        index index.php index.html index.htm;
        error_page 404 /404.html;

        location / {
            try_files \$uri \$uri/ /index.php?\$args;
        }

        # Pass PHP scripts to PHP-FPM
        location ~ \.php$ {
            try_files \$uri =403;
            fastcgi_pass unix:/var/run/php5-fpm-$DOMAIN_OWNER.sock;
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
        }

        # Enable browser cache for CSS / JS
        location ~* \.(?:css|js)$ {
            expires 30d;
            add_header Pragma "public";
            add_header Cache-Control "public";
            add_header Vary "Accept-Encoding";
        }

        # Enable browser cache for static files
        location ~* \.(?:ico|jpg|jpeg|gif|png|bmp|webp|tiff|svg|svgz|pdf|mp3|flac|ogg|mid|midi|wav|mp4|webm|mkv|ogv|wmv|eot|otf|woff|ttf|rss|atom|zip|7z|tgz|gz|rar|bz2|tar|exe|doc|docx|xls|xlsx|ppt|pptx|rtf|odt|ods|odp)$ {
            expires 60d;
            add_header Pragma "public";
            add_header Cache-Control "public";
        }

        # Deny access to hidden files
        location ~ (^|/)\. {
            deny all;
        }

        # Prevent logging of favicon and robot request errors
        location = /favicon.ico { log_not_found off; access_log off; }
        location = /robots.txt  { log_not_found off; access_log off; }
}


server {
        listen 443 ssl spdy;
        server_name www.$DOMAIN $DOMAIN;
        root $DOMAIN_PATH/public_html;
        access_log $DOMAIN_PATH/logs/access.log;
        error_log $DOMAIN_PATH/logs/error.log;

        index index.php index.html index.htm;
        error_page 404 /404.html;

        include /etc/nginx/ssl.conf;

        location / {
            try_files \$uri \$uri/ /index.php?\$args;
        }

        location ~ \.php$ {
            try_files \$uri =403;
            fastcgi_pass unix:/var/run/php5-fpm-$DOMAIN_OWNER.sock;
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
        }

        # Enable browser cache for CSS / JS
        location ~* \.(?:css|js)$ {
            expires 30d;
            add_header Pragma "public";
            add_header Cache-Control "public";
            add_header Vary "Accept-Encoding";
        }

        # Enable browser cache for static files
        location ~* \.(?:ico|jpg|jpeg|gif|png|bmp|webp|tiff|svg|svgz|pdf|mp3|flac|ogg|mid|midi|wav|mp4|webm|mkv|ogv|wmv|eot|otf|woff|ttf|rss|atom|zip|7z|tgz|gz|rar|bz2|tar|exe|doc|docx|xls|xlsx|ppt|pptx|rtf|odt|ods|odp)$ {
            expires 60d;
            add_header Pragma "public";
            add_header Cache-Control "public";
        }

        # Deny access to hidden files
        location ~ (^|/)\. {
            deny all;
        }

        # Prevent logging of favicon and robot request errors
        location = /favicon.ico { log_not_found off; access_log off; }
        location = /robots.txt  { log_not_found off; access_log off; }
}
EOF
    else # Use Apache vHost config
        cat > $DOMAIN_CONFIG_PATH <<EOF
<VirtualHost *:80>

    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    ServerAdmin admin@$DOMAIN
    DocumentRoot $DOMAIN_PATH/public_html/
    ErrorLog $DOMAIN_PATH/logs/error.log
    CustomLog $DOMAIN_PATH/logs/access.log combined

    FastCGIExternalServer $DOMAIN_PATH/php5-fpm -pass-header Authorization -idle-timeout 120 -socket /var/run/php5-fpm-$DOMAIN_OWNER.sock
    Alias /php5-fcgi $DOMAIN_PATH

</VirtualHost>


<IfModule mod_ssl.c>
<VirtualHost *:443>

    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    ServerAdmin admin@$DOMAIN
    DocumentRoot $DOMAIN_PATH/public_html/
    ErrorLog $DOMAIN_PATH/logs/error.log
    CustomLog $DOMAIN_PATH/logs/access.log combined

    # With PHP5-FPM, you need to create another PHP5-FPM pool for SSL connections
    # Adding the same fastcgiexternalserver line here will result in an error
    Alias /php5-fcgi $DOMAIN_PATH

    SSLEngine on
    SSLCertificateFile    /etc/ssl/localcerts/webserver.pem
    SSLCertificateKeyFile /etc/ssl/localcerts/webserver.key
    SSLProtocol           all -SSLv3 -SSLv2

    <FilesMatch "\.(cgi|shtml|phtml|php)$">
        SSLOptions +StdEnvVars
    </FilesMatch>

    BrowserMatch "MSIE [2-6]" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0
    BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown

</VirtualHost>
</IfModule>
EOF
    fi # End if $WEBSERVER -eq 1

    if [ $AWSTATS_ENABLE = 'yes' ]; then
        # Configure Awstats for domain
        cp /etc/awstats/awstats.conf /etc/awstats/awstats.$DOMAIN.conf
        sed -i 's/^SiteDomain=.*/SiteDomain="'${DOMAIN}'"/' /etc/awstats/awstats.$DOMAIN.conf
        sed -i 's/^LogFile=.*/\#Deleted LogFile parameter. Appended at the bottom of this config file instead./' /etc/awstats/awstats.$DOMAIN.conf
        sed -i 's/^LogFormat=.*/LogFormat=1/' /etc/awstats/awstats.$DOMAIN.conf
        sed -i 's/^DirData=.*/\#Deleted DirData parameter. Appended at the bottom of this config file instead./' /etc/awstats/awstats.$DOMAIN.conf
        sed -i 's/^DirIcons=.*/DirIcons=".\/awstats-icon"/' /etc/awstats/awstats.$DOMAIN.conf
        sed -i '/Include \"\/etc\/awstats\/awstats\.conf\.local\"/ d' /etc/awstats/awstats.$DOMAIN.conf
        echo "LogFile=\"$DOMAIN_PATH/logs/access.log\"" >> /etc/awstats/awstats.$DOMAIN.conf
        echo "DirData=\"$DOMAIN_PATH/awstats/.data\"" >> /etc/awstats/awstats.$DOMAIN.conf
    fi

    # Add new logrotate entry for domain
    cat > /etc/logrotate.d/$LOGROTATE_FILE <<EOF
$DOMAIN_PATH/logs/*.log {
    daily
    missingok
    rotate 10
    compress
    delaycompress
    notifempty
    create 0660 $DOMAIN_OWNER $DOMAIN_OWNER
    sharedscripts
    prerotate
        $AWSTATS_CMD
    endscript
    postrotate
        $POSTROTATE_CMD
    endscript
}
EOF
    # Enable domain from sites-available to sites-enabled
    ln -s $DOMAIN_CONFIG_PATH $DOMAIN_ENABLED_PATH

    # GIT
    if [ $GIT_ENABLE = 'yes' ]; then
        mkdir -p $GIT_PATH
        cd $GIT_PATH
        git init --bare
        cat > hooks/post-receive <<EOF
#!/bin/sh
    GIT_WORK_TREE=$DOMAIN_PATH git checkout -f
EOF
        chmod +x hooks/post-receive
        cd - &> /dev/null

        # Set permissions
        chown -R $DOMAIN_OWNER:$DOMAIN_OWNER $GIT_PATH
        echo -e "\033[35;1mSuccesfully Created git repository \033[0m"
        echo -e "\033[35;1mgit remote add web ssh://$DOMAIN_OWNER@$HOSTNAME_FQDN:$SSHD_PORT/$GIT_PATH \033[0m"
    fi


} # End function add_domain


function remove_domain {

    echo -e "\033[31;1mWARNING: This will permanently delete everything related to $DOMAIN\033[0m"
    echo -e "\033[31mIf you wish to stop it, press \033[1mCTRL+C\033[0m \033[31mto abort.\033[0m"
    sleep $REMOVE_DOMAIN_TIMER

    # First disable domain and reload webserver
    echo -e "* Disabling domain: \033[1m$DOMAIN\033[0m"
    sleep 1
    rm -rf $DOMAIN_ENABLED_PATH
    reload_webserver

    echo -e "* Removing domain files: \033[1m$DOMAIN_PATH\033[0m"
    sleep 1
    rm -rf $DOMAIN_PATH

    echo -e "* Removing vhost file: \033[1m$DOMAIN_CONFIG_PATH\033[0m"
    sleep 1
    rm -rf $DOMAIN_CONFIG_PATH

    echo -e "* Removing logrotate file: \033[1m/etc/logrotate.d/$LOGROTATE_FILE\033[0m"
    sleep 1
    rm -rf /etc/logrotate.d/$LOGROTATE_FILE

    echo -e "* Removing git repository: \033[1m$GIT_PATH\033[0m"
    sleep 1
    rm -rf $GIT_PATH

} # End function remove_domain


function check_domain_exists {

    # If virtualhost config exists in /sites-available or the vhost directory exists,
    # Return 0 if files exists, otherwise return 1
    if [ -e "$DOMAIN_CONFIG_PATH" ] || [ -e "$DOMAIN_PATH" ]; then
        return 0
    else
        return 1
    fi

} # End function check_domain_exists


function check_domain_valid {

    # Check if the domain entered is actually valid as a domain name
    # NOTE: to disable, set "DOMAIN_CHECK_VALIDITY" to "no" at the start of this script
    if [ "$DOMAIN_CHECK_VALIDITY" = "yes" ]; then
        if [[ "$DOMAIN" =~ [\~\!\@\#\$\%\^\&\*\(\)\_\+\=\{\}\|\\\;\:\'\"\<\>\?\,\/\[\]] ]]; then
            echo -e "\033[35;1mERROR: Domain check failed. Please enter a valid domain.\033[0m"
            echo -e "\033[35;1mERROR: If you are certain this domain is valid, then disable domain checking option at the beginning of the script.\033[0m"
            return 1
        else
            return 0
        fi
    else
    # If $DOMAIN_CHECK_VALIDITY is "no", simply exit
        return 0
    fi

} # End function check_domain_valid





#### Main program begins ####

# Show Menu
if [ ! -n "$1" ]; then
    echo ""
    echo -e "\033[35;1mSelect from the options below to use this script:- \033[0m"
    echo -n  "$0"
    echo -ne "\033[36m add user Domain.tld\033[0m"
    echo     " - Add specified domain to \"user's\" home directory. AWStats(optional) and log rotation will be configured."

    echo -n  "$0"
    echo -ne "\033[36m rem user Domain.tld\033[0m"
    echo     " - Remove everything for Domain.tld including stats and public_html. If necessary, backup domain files before executing!"

    echo -n  "$0"
    echo -ne "\033[36m dbgui on|off\033[0m"
    echo     " - Disable or enable public viewing of Adminer or phpMyAdmin."

    echo -n  "$0"
    echo -ne "\033[36m stats on|off\033[0m"
    echo     " - Disable or enable public viewing of AWStats."

    echo ""
    exit 0
fi
# End Show Menu


case $1 in
add)
    # Add domain for user
    # Check for required parameters
    if [ $# -ne 3 ]; then
        echo -e "\033[31;1mERROR: Please enter the required parameters.\033[0m"
        exit 1
    fi

    # Set up variables
    DOMAIN_OWNER=$2
    DOMAIN=$3
    initialize_variables

    # Check if user exists on system
    if [ ! -d /home/$DOMAIN_OWNER ]; then
        echo -e "\033[31;1mERROR: User \"$DOMAIN_OWNER\" does not exist on this system.\033[0m"
        echo -e " - \033[34mUse \033[1madduser\033[0m \033[34m to add the user to the system.\033[0m"
        echo -e " - \033[34mFor more information, please see \033[1mman adduser\033[0m"
        exit 1
    fi

    # Check if domain is valid
    check_domain_valid
    if [ $? -ne 0 ]; then
        exit 1
    fi

    # Check if domain config files exist
    check_domain_exists
    if [  $? -eq 0  ]; then
        echo -e "\033[31;1mERROR: $DOMAIN_CONFIG_PATH or $DOMAIN_PATH already exists. Please remove before proceeding.\033[0m"
        exit 1
    fi

    add_domain
    reload_webserver
    echo -e "\033[35;1mSuccesfully added \"${DOMAIN}\" to user \"${DOMAIN_OWNER}\" \033[0m"
    echo -e "\033[35;1mYou can now upload your site to $DOMAIN_PATH/public_html.\033[0m"
    echo -e "\033[35;1mAdminer/phpMyAdmin is DISABLED by default. URL = http://$DOMAIN/dbgui.\033[0m"
    echo -e "\033[35;1mAWStats is DISABLED by default. URL = http://$DOMAIN/stats.\033[0m"
    echo -e "\033[35;1mStats update daily. Allow 24H before viewing stats or you will be greeted with an error page. \033[0m"
    echo -e "\033[35;1mIf Varnish cache is enabled, please disable & enable it again to reconfigure this domain. \033[0m"
    ;;
rem)
    # Add domain for user
    # Check for required parameters
    if [ $# -ne 3 ]; then
        echo -e "\033[31;1mERROR: Please enter the required parameters.\033[0m"
        exit 1
    fi

    # Set up variables
    DOMAIN_OWNER=$2
    DOMAIN=$3
    initialize_variables

    # Check if user exists on system
    if [ ! -d /home/$DOMAIN_OWNER ]; then
        echo -e "\033[31;1mERROR: User \"$DOMAIN_OWNER\" does not exist on this system.\033[0m"
        exit 1
    fi

    # Check if domain config files exist
    check_domain_exists
    # If domain doesn't exist
    if [ $? -ne 0 ]; then
        echo -e "\033[31;1mERROR: $DOMAIN_CONFIG_PATH and/or $DOMAIN_PATH does not exist, exiting.\033[0m"
        echo -e " - \033[34;1mNOTE:\033[0m \033[34mThere may be files left over. Please check manually to ensure everything is deleted.\033[0m"
        exit 1
    fi

    remove_domain
    ;;
dbgui)
    if [ "$2" = "on" ]; then
        dbgui_on
    elif [ "$2" = "off" ]; then
        dbgui_off
    fi
    ;;
stats)
    if [ "$2" = "on" ]; then
        awstats_on
    elif [ "$2" = "off" ]; then
        awstats_off
    fi
    ;;
esac
