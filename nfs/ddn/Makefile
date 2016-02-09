# $Id: $
# $Date: $
#
Name= certify-nfs-ddn
Version= 3.6
Release= 6.centos6_x86_64.jwics
Distro= centos6_x86_64
Source= ${Name}-${Version}-${Release}.tgz

RPMBUILD= ${HOME}/rpmbuild
RPM_BUILD_ROOT= ${RPMBUILD}/BUILDROOT

CRON_DIR= /etc/cron.daily
DOC_DIR= /usr/share/doc/${Name}-${Version}
SBIN_DIR= /usr/local/sbin
ETC_DIR= /usr/local/etc

CRON_FILES= ddn_diskscan.cron

DOC_FILES= readme

SBIN_FILES= ddn_diskscan.sh \
	ddndsh

ETC_FILES=
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

install: make_path
	@for file in ${CRON_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${CRON_DIR}; \
	done
	@for file in ${DOC_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${DOC_DIR}; \
	done
	@for file in ${SBIN_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${SBIN_DIR}; \
	done

localinstall:
	@for file in ${SBIN_FILES}; do \
		install -p $$file ${SBIN_DIR}; \
	done

make_path:
	@if [ ! -d ${RPM_BUILD_ROOT}/${CRON_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${CRON_DIR}; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/${DOC_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${DOC_DIR}; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/${SBIN_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${SBIN_DIR}; \
	fi;

clean:
	@rm -f ${RPMBUILD}/SPECS/${Name}-${Version}-${Release}.spec
	@rm -fR ${RPMBUILD}/SOURCES/${Source}
	@rm -fR ${RPMBUILD}/BUILD/${Name}
	@rm -fR ${RPMBUILD}/BUILDROOT/*

