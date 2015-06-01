#!/usr/bin/perl -w
# $Id: Makefile.PL 563 2014-10-03 20:38:37Z rohare $
# $URL: file:///usr/local/svn/certify/trunk/db/Makefile.PL $
#

@ARGV == 2 or die "not enough arguments: $!\n";

my $net = $ARGV[0];
my $distro = $ARGV[1];

$file = 'Makefile';
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

$SvnVersion = `svnversion`;
chomp $SvnVersion;
($SvnVersion =~ /:/ || $SvnVersion =~ /M/) and warn "Warning: modified svn state\n";
$SvnVersion =~ s/:.*//;
$SvnVersion =~ s/M//;
$SvnVersion =~ s/\..*$//g;
if ($input_scalar =~ /^SvnVersion= /m) {
	my $origStr = '^SvnVersion=.*$';
	my $replStr = "SvnVersion= $SvnVersion";
	$input_scalar =~ s/$origStr/$replStr/m;
}

my $release = `lsb_release -sr`;
chomp $release;
$release =~ s/\..*//;

my $arch = `uname -i`;
chomp $arch;

if ($input_scalar =~ /^Release= /m) {
	my $origStr = '^Release=.*$';
	my $replStr = "Release= ${SvnVersion}.${distro}${release}_${arch}.${net}";
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

