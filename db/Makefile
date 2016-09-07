# $Id: Makefile 565 2014-10-24 16:42:13Z rohare $
# $Date:$
#
Name= certify-db
Version=1.0
Distro= centos7_x86_64
Release= 1.centos7_x86_64.ohares
Source= ${Name}-${Version}-${Release}.tgz

RPMBUILD= ${HOME}/rpmbuild
RPM_BUILD_ROOT= ${RPMBUILD}/BUILDROOT

DOC_DIR= /usr/share/doc/${Name}-${Version}

DOC_FILES= dump.out \
	readme

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

install: make_path doc

make_path:
	@if [ ! -d ${RPM_BUILD_ROOT}/${DOC_DIR} ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/${DOC_DIR}; \
	fi;
	@if [ ! -d ${RPM_BUILD_ROOT}/root ]; then \
		mkdir -m 0755 -p ${RPM_BUILD_ROOT}/root; \
	fi;

doc:
	@for file in ${DOC_FILES}; do \
		install -p $$file ${RPM_BUILD_ROOT}/${DOC_DIR}; \
	done

clean:
	@rm -f ${RPMBUILD}/SPECS/${Name}-${Version}-${Release}.spec
	@rm -fR ${RPMBUILD}/SOURCES/${Source}
	@rm -fR ${RPMBUILD}/BUILD/${Name}
	@rm -fR ${RPMBUILD}/BUILDROOT/*

