#!/usr/bin/perl -w
# $Id$
# $Date$
#
# repoWebLoad.pl
# Copy our FIE rpms to the webserver
use strict;
use File::Copy;

my $debug = 0;
my $BASE_DIR = "/var/www/html/software/zdiv";

# RPMS source directory
my $dir = $ARGV[0];
if (not defined $dir) {
	$dir = $ENV{"HOME"} . "/rpmbuild/RPMS";
	print "RPM source directory [$dir]: ";
	my $ans = <STDIN>;
	chomp $ans;
	if ($ans ne "") {
		$dir = $ans;
	}
}

-d $dir or die "rpmbuild directory does not exist";
my $basedir = $dir;

# Push rpms to web server
foreach my $subdir ("i386","x86_64","noarch") {
	$dir = $basedir . "/" . $subdir;
	if (-d $dir) { 
		$debug && print "$dir\n";
		opendir(DIR, "$dir") or warn "Can't open $dir";
		while (my $file = readdir(DIR)) {
			$file =~ /^certify-/ or next;
			-d $dir or die "missing destination directory";

			my $distro = "centos";
			if ($file =~ "el5") { 
				my $dest = $BASE_DIR . "//centos/5/noarch";
				$debug && print "install -m 644 $dir/$file $dest/$file\n";
				`install -m 644 $dir/$file $dest/$file`;
			}
			if ($file =~ "el6") { 
				my $dest = $BASE_DIR . "//centos/6/noarch";
				$debug && print "install -m 644 $dir/$file $dest/$file\n";
				`install -m 644 $dir/$file $dest/$file`;
			}
			if ($file =~ "el7") { 
				my $dest = $BASE_DIR . "//centos/7/noarch";
				$debug && print "install -m 644 $dir/$file $dest/$file\n";
				`install -m 644 $dir/$file $dest/$file`;
			}
			$distro = "redhat";
			if ($file =~ "el5") { 
				my $dest = $BASE_DIR . "//redhat/5/noarch";
				$debug && print "install -m 644 $dir/$file $dest/$file\n";
				`install -m 644 $dir/$file $dest/$file`;
			}
			if ($file =~ "el6") { 
				my $dest = $BASE_DIR . "//redhat/6/noarch";
				$debug && print "install -m 644 $dir/$file $dest/$file\n";
				`install -m 644 $dir/$file $dest/$file`;
			}
			if ($file =~ "el7") { 
				my $dest = $BASE_DIR . "//redhat/7Server/noarch";
				$debug && print "install -m 644 $dir/$file $dest/$file\n";
				`install -m 644 $dir/$file $dest/$file`;

				$dest = $BASE_DIR . "//redhat/7Workstation/noarch";
				$debug && print "install -m 644 $dir/$file $dest/$file\n";
				`install -m 644 $dir/$file $dest/$file`;
			}
		}
		close DIR;
	}
}

