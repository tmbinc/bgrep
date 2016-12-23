#
# Regular cron jobs for the bgrep package
#
0 4	* * *	root	[ -x /usr/bin/bgrep_maintenance ] && /usr/bin/bgrep_maintenance
