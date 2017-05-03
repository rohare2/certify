#!/usr/bin/perl -w
# Makefile.PL
# $Id$
# $Date$
#
use strict;

my $debug = 0;

my $baseDir = `pwd`;
chomp $baseDir;

system("git log > changelog");

sub changeFiles {
	# Makefile
	my $file = 'Makefile';
	open (INPUT,"<$file") or die;
	my @input_array=<INPUT>;
	close(INPUT);
	my $input_scalar=join("",@input_array);
	my ($origStr, $replStr);

	-f "VERSION" or die "No version file";
	my $version = `cat VERSION`;
	chomp $version;
	if ($input_scalar =~ /^Version= /m) {
		my $origStr = '^Version=.*$';
		my $replStr = "Version= $version";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	-f "RELEASE" or die "No release file";
	my $releaseNo = `cat RELEASE`;
	chomp $releaseNo;

	if ($input_scalar =~ /^Release= /m) {
		my $origStr = '^Release=.*$';
		my $replStr = "Release= ${releaseNo}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	open (OUTPUT, "> $file") or die;
	print OUTPUT "$input_scalar";
	close OUTPUT;

}

# Build rpms
sub buildRPMS {
	chdir "$baseDir";
	changeFiles();
	system("make rpmbuild");
}

buildRPMS();
`rm changelog`;

# PGP sign the rpms
print "Sign RPM packages\n";
system("rpm --addsign $ENV{HOME}/rpmbuild/RPMS/noarch/certify*.rpm");

exit 0;
