# certify_config.py
# $Id$
# $Date: $
import re
import sys

# Global settings
minlen = 10
pass_max_days = 180
logfile = '/var/log/certify'

if __name__ == '__main__':
	print "This is the certify configuration file and is not ment to be executed directly"
	sys.exit(0)

#
# Operating system approval codes
#  1) approved, 2) testing, 3) waiting for ISSO approval
REVIEW_STATUS = {
	'5.10':'2',
	'ch4':'2',
	'ch5':'2',
	'el5':'1',
	'el6':'1',
	'el7':'1',
	'fc14':'2',
	'fc15':'2',
	'fc16':'2',
	'fc17':'1' }

# Operating system lists
sysvList = ('5.10', 'ch4', 'ch5', 'el5', 'el6', 'fc14', 'fc15', 'fc16', 'fc17')
systemdList = ('el7')

# General environment setup
use_ad_auth = 0 # Using Active Directory authentication
use_ipa_auth = 0 # Using IPA Identity Managment

# PAM Stack Options
use_cracklib = 1 # $use_cracklib instead of passwdqc
use_passwdqc = 0 # $use_passwdqc instead of cracklib
use_pamtally = 0 # $use_pam_tally

# cracklib options
cracklib = {
	'retry':'3',
	'difok':'',
	'minlen':minlen, # Minimum acceptable size (plus one if credits not disabled)
	'dcredit':'0',
	'ucredit':'0',
	'lcredit':'0',
	'ocredit':'0',
	'minclass':'4',
	'maxrepeat':'0',
	'maxsequence':'0',
	'maxclassrepeat':'0',
	'reject_username':'1',
	'gecoscheck':'',
	'enforce_for_root':'',
	'use_authtok':'',
	'try_first_pass':'1' }

# loginDefs
logindefs = {
	'PASS_MAX_DAYS':pass_max_days,
	'PASS_MIN_DAYS':'0',
	'PASS_MIN_LEN':minlen,
	'MD5_CRYPT_ENAB':'yes',
	'UMASK':'077' }

# passwdqc config
N0 = "disabled"
N1 = "disabled"
N2 = "disabled"
N3 = "disabled"
N4 = minlen
MIN = "min=" + str(N0) + "," + str(N1) + "," + str(N2) + "," + str(N3) + "," + str(N4)

# Pam Tally Options
pam_tally = {
	'version':'2',
	'deny':'3',
	'lock_time':'',
	'unlock_time':'600',
	'magic_root':'',
	'even_deny_root':'',
	'root_unlock_time':'600' }

# sshd_config settings
sshd_option = {
	'Protocol':'2',
	'UsePAM':'yes',
	'StrictModes':'yes',
	'HostbasedAuthentication':'no',
	'PermitEmptyPasswords':'no',
	'PermitRootLogin':'no',
	'RSAAuthentication':'no',
	'X11Forwarding':'yes',
	'PrintMotd':'yes',
	'PrintLastLog':'yes',
	'Banner':'/etc/issue.net' }

# Unix services
alwaysDisable = ('bluetooth','isdn','pcmcia')
ipfwd = 'n'
USB_STORAGE = 'y'

# System logs
LOG_ROT_SCHED = "monthly"
LOG_ROT_KEEP = "6"
loglist = ('/var/log/messages','/var/log/secure')

# auditd config
audit_option = {
	'log_file':"/var/log/audit/audit.log",
	'log_format':'RAW',
	'log_group':'root',
	'priority_boost':'4',
	'flush':'INCREMENTAL',
	'freq':'20',
	'num_logs':'5',
	'disp_qos':'lossy',
	'dispatcher':"/sbin/audispd",
	'name_format':'NONE',
	'max_log_file':'6',
	'max_log_file_action':'ROTATE',
	'space_left':'75',
	'space_left_action':'SYSLOG',
	'action_mail_acct':'root',
	'admin_space_left':'50',
	'admin_space_left_action':'SUSPEND',
	'disk_full_action':'SUSPEND',
	'disk_error_action':'SUSPEND',
	'tcp_listen_queue':'5',
	'tcp_max_per_addr':'1',
	'tcp_client_max_idle':'0',
	'enable_krb5':'no',
	'krb5_principal':'auditd' }

hosts_allow = [
	'ALL : KNOWN',
	'ALL : LOCAL' ]

hosts_deny = [
	'ALL : ALL' ]

chkdirs = (
	'/bin',
	'/boot',
	'/dev',
	'/etc',
	'/lib',
	'/lib64',
	'/opt',
	'/root',
	'/sbin',
	'/sys',
	'/usr',
	'/var'
)

# Unique to Solaris
LOCK_AFTER_RETRIES = 'YES'
MINDIFF = 3
MINALPHA = 1
MINNONALPHA = 1
MINLOWER = 1
MAXREPEATS = 1
MINSPECIAL = 1
MINDIGIT = 1

# Banners
BANNER_OHARES = """
        **WARNING**WARNING**WARNING**WARNING**WARNING** 

 This is a private ohares.us computer system. All data contained
 within ohares.us computer systems is owned by ohares.us, and
 may be audited, intercepted, recorded, read, copied, or captured
 in any manner and disclosed in any manner, by authorized personnel.
 THERE IS NO RIGHT OF PRIVACY IN THIS SYSTEM. System personnel may
 disclose any potential evidence of crime found on ohares.us
 computer systems to appropriate authorities.
  
 USE OF THIS SYSTEM BY ANY USER, AUTHORIZED OR UNAUTHORIZED,
 CONSTITUTES CONSENT TO THIS AUDITING, INTERCEPTION, RECORDING,
 READING, COPYING, CAPTURING, AND DISCLOSURE OF COMPUTER ACTIVITY.

        **WARNING**WARNING**WARNING**WARNING**WARNING** 
"""

BANNER_LLNL = """
        **WARNING**WARNING**WARNING**WARNING**WARNING**

 This is a Department of Energy (DOE) computer system. DOE
 computer systems are provided for the processing of official
 U.S. Government information only. All data contained within
 DOE computer systems is owned by the DOE, and may be audited,
 intercepted, recorded, read, copied, or captured in any
 manner and disclosed in any manner, by authorized personnel.
 THERE IS NO RIGHT OF PRIVACY IN THIS SYSTEM. System personnel
 may disclose any potential evidence of crime found on DOE
 computer systems to appropriate authorities.

 USE OF THIS SYSTEM BY ANY USER, AUTHORIZED OR UNAUTHORIZED,
 CONSTITUTES CONSENT TO THIS AUDITING, INTERCEPTION, RECORDING,
 READING, COPYING, CAPTURING, AND DISCLOSURE OF COMPUTER ACTIVITY.

        **WARNING**WARNING**WARNING**WARNING**WARNING**
"""

def oschk(os,release):
	p = re.compile('\.el5\.?')
	m = p.search(release)
	if m:
		return 'el5'
	p = re.compile('\.el6\.')
	m = p.search(release)
	if m:
		return 'el6'
	p = re.compile('\.el7\.')
	m = p.search(release)
	if m:
		return 'el7'
	p = re.compile('\.fc14\.')
	m = p.search(release)
	if m:
		return 'fc14'
	p = re.compile('\.fc15\.')
	m = p.search(release)
	if m:
		return 'fc15'
	p = re.compile('\.fc16\.')
	m = p.search(release)
	if m:
		return 'fc16'
	p = re.compile('\.fc17\.')
	m = p.search(release)
	if m:
		return 'fc17'

cronsched = {
	'md5check':'daily',
	'fullcheck':'weekly',
	'harden':'monthly'
}

