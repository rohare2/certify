#!/usr/bin/perl -w
# $Id$
# $Date$
#
# repoWebLoad.pl
#
use strict;
use File::Copy;

my $debug = 0;
my $BASE_DIR = "/var/www/html/software";

# RPMS source directory
my $dir = $ENV{"HOME"} . "/rpmbuild/RPMS/noarch";
print "RPM source directory [$dir]: ";
my $ans = <STDIN>;
chomp $ans;
if ($ans ne "") {
	$dir = $ans;
}

-d $dir or die "rpmbuild directory does not exist";

# Push rpms to web server
if (-d $dir) { 
	opendir(DIR, "$dir") or warn "Can't open $dir";
	while (my $file = readdir(DIR)) {
		my $dest;
		$file =~ /^certify-/ or next;

		$dest = $BASE_DIR . "/certify";
		$debug && print "install -m 644 $dir/$file $dest/$file\n";
		`install -m 644 $dir/$file $dest/$file`;
		! $debug && `rm $dir/$file`;
	}
	close DIR;
}
