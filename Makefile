# Makefile
# $Id: $
# $Date: $
#
Name= certify
Version= 3.2
Release= 564.centos6_x86_64.gs
Distro= centos6_x86_64
Source= ${Name}-${Version}-${Release}.tgz
BASE= $(shell pwd)

RPMBUILD= ${HOME}/rpmbuild
RPM_BUILD_ROOT= ${RPMBUILD}/BUILDROOT

CERTIFY_DIR= /usr/local/certify
GCONF_DIR= /etc/gconf/gconf.xml.mandatory
GDM_DIR= /etc/gdm
DOC_DIR= /usr/share/doc/${Name}-${Version}
SBIN_DIR= /usr/local/sbin

SCRIPT_FILES= check.py \
	certify_config.py \
	diskcheck.sh \
	diskscan.sh \
	harden.py \
	testPassword.py

SBIN_FILES= diskcheck.sh \
	diskscan.sh

GCONF_FILES= %gconf-tree.xml

GDM_FILES= banner.png

DOC_FILES= banner.png.llnl \
	banner.png.sample \
	changelog \
	readme


CRON_WEEKLY_FILES= certify_check.cron

CRON_DAILY_FILES= certify_harden.cron \
	certify_md5chk.cron \
	diskcheck.cron \
	diskscan.cron

MY_CNF= my.cnf.certify

rpmbuild: specfile source
	rpmbuild -bb --buildroot ${RPM_BUILD_ROOT} ${RPMBUILD}/SPECS/${Name}-${Version}-${Release}.spec

specfile: spec
	@cat ./spec | sed "s/(release)/${Release}/" \
		| sed "s?(version)?${Version}?" \
		| sed "s?(source)?${Source}?" \
		> ${RPMBUILD}/SPECS/${Name}-${Version}-${Release}.spec 

source:
	if [ ! -d ${RPMBUILD}/SOURCES/${Name} ]; then \
		mkdir ${RPMBUILD}/SOURCES/${Name}; \
	fi
	rsync -av * ${RPMBUILD}/SOURCES/${Name}
	tar czvf ${RPMBUILD}/SOURCES/${Source} --exclude=.svn -C ${RPMBUILD}/SOURCES ${Name}
	rm -fr ${RPMBUILD}/SOURCES/${Name}

install: make_path gconf gdm doc sbin cron mysql
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
	@if [ ! -d ${RPM_BUILD_ROOT}/usr/local/sbin ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/usr/local/sbin; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/root ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/root; \
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

sbin:
	@for file in ${SBIN_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${SBIN_DIR}; \
	done;

cron: cronweekly crondaily

cronweekly:
	@for file in ${CRON_WEEKLY_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/etc/cron.weekly; \
	done;

crondaily:
	@for file in ${CRON_DAILY_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/etc/cron.daily; \
	done;

mysql:
	@install -p ${MY_CNF} ${RPM_BUILD_ROOT}/root/.my.cnf.certify;

clean:
	@rm -f ${RPMBUILD}/SPECS/${Name}-${Version}-${Release}.spec
	@rm -fR ${RPMBUILD}/SOURCES/${Source}
	@rm -fR ${RPMBUILD}/BUILD/${Name}
	@rm -fR ${RPMBUILD}/BUILDROOT/*

