#!/usr/bin/perl -w
# Makefile.PL
# $Id$
# $Date$

# check arguments
@ARGV == 2 or die "not enough arguments: $!\n";

my $net = $ARGV[0];
my $distro = $ARGV[1];

$file = 'Makefile';
open (INPUT,"<$file") or die;
my @input_array=<INPUT>;
close(INPUT);
my $input_scalar=join("",@input_array);
my ($origStr, $replStr);

-f "../../VERSION" or die "No version file";
my $version = `cat ../../VERSION`;
chomp $version;
if ($input_scalar =~ /^Version=/m) {
	my $origStr = '^Version=.*$';
	my $replStr = "Version= $version";
	$input_scalar =~ s/$origStr/$replStr/m;
}

-f "../../RELEASE" or die "No release file";
my $releaseNo = `cat ../../RELEASE`;
chomp $releaseNo;

my $release = `lsb_release -sr`;
chomp $release;
$release =~ s/\..*//;

my $arch = `uname -i`;
chomp $arch;

if ($input_scalar =~ /^Release= /m) {
	my $origStr = '^Release=.*$';
	my $replStr = "Release= ${releaseNo}.${distro}${release}_${arch}.${net}";
	$input_scalar =~ s/$origStr/$replStr/m;
}

if ($input_scalar =~ /^Distro= /m) {
	my $origStr = '^Distro=.*$';
	my $replStr = "Distro= ${distro}${release}_${arch}";
	$input_scalar =~ s/$origStr/$replStr/m;
}

open (OUTPUT, "> $file") or die;
print OUTPUT "$input_scalar";
close OUTPUT;

system("make rpmbuild");
