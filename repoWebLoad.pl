#!/usr/bin/perl -w
# $Id$
# $Date: $
#
# repoWebLoad.pl
#
use strict;
use File::Copy;

my $debug = 0;
my $BASE_DIR = "/var/www/html/software";

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
foreach my $subdir ("noarch") {
	$dir = $basedir . "/" . $subdir;
	if (-d $dir) { 
		print "$dir\n";
		opendir(DIR, "$dir") or warn "Can't open $dir";
		while (my $file = readdir(DIR)) {
			my ($distro,$arch,$dest);
			$file =~ /^certify-/ or next;

			foreach my $distro ("redhat/5Client","redhat/5Server","redhat/6Server",
				"redhat/6Workstation","redhat/7Server","redhat/7Workstation",
				"centos/5","centos/6","centos/7") {
				$arch = 'noarch';
				-d $dir or die "missing destination directory";
				$dest = $BASE_DIR . "/" . $distro . "/" . $arch;
				$debug && print "install -m 644 $dir/$file $dest/$file\n";
				`install -m 644 $dir/$file $dest/$file`;
			}
		}
		close DIR;
	}
}
