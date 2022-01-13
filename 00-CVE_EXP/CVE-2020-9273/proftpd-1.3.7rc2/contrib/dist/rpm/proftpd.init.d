#!/bin/sh
#
# Startup script for ProFTPD
#
# chkconfig: - 85 15
# description: ProFTPD is an enhanced FTP server with a focus towards \
#              simplicity, security, and ease of configuration. \
#              It features a very Apache-like configuration syntax, \
#              and a highly customizable server infrastructure, \
#              including support for multiple 'virtual' FTP servers, \
#              anonymous FTP, and permission-based directory visibility.
# processname: proftpd
# config: /etc/proftpd.conf
# pidfile: /var/run/proftpd/proftpd.pid

### BEGIN INIT INFO
# Provides: proftpd ftpserver
# Required-Start: $local_fs $network $named $remote_fs
# Required-Stop: $local_fs $network $named $remote_fs
# Default-Stop: 0 1 6
# Short-Description: ProFTPd FTP Server
# Description: ProFTPd is an enhanced FTP server with a focus towards
#       simplicity, security, and ease of configuration.
#       It features a very Apache-like configuration syntax,
#       and a highly customizable server infrastructure,
#       including support for multiple 'virtual' FTP servers,
#       anonymous FTP, and permission-based directory visibility.
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

# Source ProFTPD configuration.
PROFTPD_OPTIONS=""
if [ -f /etc/sysconfig/proftpd ]; then
      . /etc/sysconfig/proftpd
fi

# Check that networking is enabled.
[ ${NETWORKING} = "no" ] && exit 1

# Make sure the binary is present.
[ -x /usr/sbin/proftpd ] || exit 5

RETVAL=0
prog="proftpd"

start() {
	echo -n $"Starting $prog: "
	daemon proftpd $PROFTPD_OPTIONS 2>/dev/null
	RETVAL=$?
	echo
	[ $RETVAL -eq 0 ] && touch /var/lock/subsys/proftpd
}

stop() {
	echo -n $"Shutting down $prog: "
	killproc proftpd
	RETVAL=$?
	echo
	[ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/proftpd
}

# See how we were called.
case "$1" in
	start)
		start
		;;
	stop)
		stop
		;;
	status)
		status proftpd
		RETVAL=$?
		;;
	restart)
		stop
		start
		;;
	try-restart|condrestart)
		if [ -f /var/lock/subsys/proftpd ]; then
			stop
			start
		fi
		;;
	reload|force-reload|reread)
		echo -n $"Re-reading $prog configuration: "
		killproc proftpd -HUP
		RETVAL=$?
		echo
		;;
	configtest)
		echo -n $"Testing $prog configuration: "
		proftpd -n -t
		RETVAL=$?
		echo
		;;
	suspend)
		hash ftpshut >/dev/null 2>&1
		if [ $? = 0 ]; then
			if [ $# -gt 1 ]; then
				shift
				echo -n "Suspending with '$*'"
				ftpshut "$@"
				RETVAL=$?
			else
				echo -n "Suspending NOW"
				ftpshut now "Maintenance in progress"
				RETVAL=$?
			fi
		else
			echo -n "No way to suspend"
			RETVAL=1
		fi
		echo
		;;
	resume)
		if [ -f /etc/shutmsg ]; then
			echo -n "Allowing sessions again"
			rm -f /etc/shutmsg
		else
			echo -n "Was not suspended"
			RETVAL=2
		fi
		echo
		;;
	*)
		echo -n "Usage: $prog {start|stop|restart|try-restart|reload|status|reread|resume"
		hash ftpshut
		if [ $? = 1 ]; then
			echo '}'
		else
			echo '|suspend}'
			echo 'suspend accepts additional arguments, which are passed to ftpshut(8)'
		fi
		exit 2
esac

exit $RETVAL
