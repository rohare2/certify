#$Id: 8358f4627abc6a605d650f0e3cc76828b21c88e2 $
# $Date: Thu Sep 3 08:40:55 2015 -0700$
#
Name= certify
Version= 3.8
Release= 4
Source= ${Name}-${Version}-${Release}.tgz
BASE= $(shell pwd)

RPMBUILD= ${HOME}/rpmbuild
RPM_BUILD_ROOT= ${RPMBUILD}/BUILDROOT

CERTIFY_DIR= /usr/local/certify
GCONF_DIR= /etc/gconf/gconf.xml.mandatory
GDM_DIR= /etc/gdm
DOC_DIR= /usr/share/doc/${Name}-${Version}
FIREWALLD_DIR= /etc/firewalld/services
SBIN_DIR= /usr/local/sbin

SCRIPT_FILES= check.py \
	certify_config.py \
	harden.py \
	testPassword.py

GCONF_FILES= %gconf-tree.xml

GDM_FILES= banner.png

DOC_FILES= banner.png.llnl \
	banner.png.sample \
	changelog \
	readme

CRON_DAILY_FILES= certify_md5chk.cron

CRON_WEEKLY_FILES= certify_check.cron

CRON_MONTHLY_FILES= certify_harden.cron

FIREWALLD_FILES= simpana.xml \
	splunk.xml

SBIN_FILES= aide_check \
	aide_update

rpmbuild: specfile source
	rpmbuild -bb --buildroot ${RPM_BUILD_ROOT} ${RPMBUILD}/SPECS/${Name}-${Version}-${Release}.spec

specfile: spec
	cat ./spec > ${RPMBUILD}/SPECS/${Name}-${Version}-${Release}.spec

source:
	if [ ! -d ${RPMBUILD}/SOURCES/${Name} ]; then \
		mkdir ${RPMBUILD}/SOURCES/${Name}; \
	fi
	rsync -av * ${RPMBUILD}/SOURCES/${Name}
	tar czvf ${RPMBUILD}/SOURCES/${Source} --exclude=.git -C ${RPMBUILD}/SOURCES ${Name}
	rm -fr ${RPMBUILD}/SOURCES/${Name}

install: make_path gconf gdm doc cron rotate firewalld sbin
	@for file in ${SCRIPT_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${CERTIFY_DIR}; \
	done

make_path:
	@if [ ! -d ${RPM_BUILD_ROOT}/${CERTIFY_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${CERTIFY_DIR}; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/${GCONF_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${GCONF_DIR}; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/${GDM_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${GDM_DIR}; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/${DOC_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${DOC_DIR}; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/etc/cron.daily ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/etc/cron.daily; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/etc/cron.weekly ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/etc/cron.weekly; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/etc/cron.monthly ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/etc/cron.monthly; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/etc/logrotate.d ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/etc/logrotate.d; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/usr/local/certify/savedfiles ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/usr/local/certify/savedfiles; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/${FIREWALLD_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${FIREWALLD_DIR}; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/var/log/certify ]; then \
		mkdir -m 0740 -p ${RPM_BUILD_ROOT}/var/log/certify; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/usr/local/sbin ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/usr/local/sbin; \
	fi;

gconf:
	@for file in ${GCONF_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${GCONF_DIR}; \
	done;

gdm:
	@for file in ${GDM_FILES}; do \
		if [ -f ${RPM_BUILD_ROOT}/${GDM_DIR}/$$file ]; then \
			cp ${RPM_BUILD_ROOT}/${GDM_DIR}/$$file ${RPM_BUILD_ROOT}/${GDM_DIR}/$${file}.preharden; \
		fi; \
		install -p $$file ${RPM_BUILD_ROOT}/${GDM_DIR}; \
	done;

doc:
	@for file in ${DOC_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${DOC_DIR}; \
	done;

cron: crondaily cronweekly cronmonthly

crondaily:
	@for file in ${CRON_DAILY_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/etc/cron.daily; \
	done;

cronweekly:
	@for file in ${CRON_WEEKLY_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/etc/cron.weekly; \
	done;

cronmonthly:
	@for file in ${CRON_MONTHLY_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/etc/cron.monthly; \
	done;

rotate:
	@install -p certify ${RPM_BUILD_ROOT}/etc/logrotate.d/certify;

firewalld:
	@for file in ${FIREWALLD_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${FIREWALLD_DIR}/; \
	done;

sbin:
	@for file in ${SBIN_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${SBIN_DIR}/; \
	done;

clean:
	@rm -f ${RPMBUILD}/SPECS/${Name}-${Version}-${Release}.spec
	@rm -fR ${RPMBUILD}/SOURCES/${Source}
	@rm -fR ${RPMBUILD}/BUILD/${Name}
	@rm -fR ${RPMBUILD}/BUILDROOT/*

