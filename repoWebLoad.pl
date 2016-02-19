#!/usr/bin/perl -w
# $Id$
# $Date$
#
# repoWebLoad.pl
#
use strict;
use File::Copy;

my $debug = 1;
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
foreach my $subdir ("i386","x86_64","noarch") {
	$dir = $basedir . "/" . $subdir;
	if (-d $dir) { 
		print "$dir\n";
		opendir(DIR, "$dir") or warn "Can't open $dir";
		while (my $file = readdir(DIR)) {
			my ($net,$distro,$arch,$dest);
			$file =~ /^certify-/ or next;

			$file =~ /\.gs\./ && ($net = 'gs');
			$file =~ /\.hal\./ && ($net = 'hal');
			$file =~ /\.jwics\./ && ($net = 'jwics');
			defined $net or die "No net defined for: $file";

			$file =~ /\.redhat5_client\./ && ($distro = 'redhat/5Client');
			$file =~ /\.redhat5_server\./ && ($distro = 'redhat/5Server');
			$file =~ /\.redhat6_server\./ && ($distro = 'redhat/6Server');
			$file =~ /\.redhat6_workstation\./ && ($distro = 'redhat/6Workstation');
			$file =~ /\.redhat7_server\./ && ($distro = 'redhat/7Server');
			$file =~ /\.redhat7_workstation\./ && ($distro = 'redhat/7Workstation');
			$file =~ /\.centos5\./ && ($distro = 'centos/5');
			$file =~ /\.centos6\./ && ($distro = 'centos/6');
			$file =~ /\.centos7\./ && ($distro = 'centos/7');
			defined $distro or die "No distro defined for: $file";

			$file =~ /\.x86_64\./ && ($arch = 'x86_64');
			$file =~ /\.i386\./ && ($arch = 'i386');
			$file =~ /\.noarch\./ && ($arch = 'noarch');
			defined $arch or die "No arch defined for: $file";

			-d $dir or die "missing destination directory";
			$dest = $BASE_DIR . "/" . $net . "/" . $distro . "/" . $arch;
			$debug && print "install -m 644 $dir/$file $dest/$file\n";
			`install -m 644 $dir/$file $dest/$file`;
		}
		close DIR;
	}
}
