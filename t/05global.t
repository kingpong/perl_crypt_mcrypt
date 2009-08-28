#!/usr/bin/env perl
#
# 05global.t
#
# Test mcrypt global functions.
#
# Philip Garrett <cpan@pgarrett.net>
#
use strict;
use Test::More tests => 15;
use Crypt::Mcrypt::API qw(:all);

my @algos = mcrypt_list_algorithms();
ok(@algos != 0, "mcrypt_list_algorithms - success");

# twofish is an arbitrary choice for an algorithm to check
my $twofish = grep { /twofish/ } @algos;
ok($twofish, "mcrypt_list_algorithms - algo listed");

my @modes = mcrypt_list_modes();
ok(@modes != 0, "mcrypt_list_modes - success");

# cbc is an arbitrary choice for a mode to check
my $cbc = grep { /cbc/ } @modes;
ok($cbc, "mcrypt_list_modes - mode listed");

my $ver = mcrypt_check_version("2.0.0");
is($ver, LIBMCRYPT_VERSION(), "mcrypt_check_version - success");
$ver = mcrypt_check_version(undef);
is($ver, LIBMCRYPT_VERSION(), "mcrypt_check_version - null param success");
$ver = mcrypt_check_version();
is($ver, LIBMCRYPT_VERSION(), "mcrypt_check_version - no param success");
$ver = mcrypt_check_version("100.0.0");
ok(!$ver, "mcrypt_check_version - failure");
$ver = mcrypt_check_version('');
ok(!$ver, "mcrypt_check_version - empty param failure");

my $errstr = mcrypt_strerror(-1);
is($errstr, "Unknown error.\n", "mcrypt_strerror - success");
$errstr = mcrypt_strerror(undef);
ok(!$errstr, "mcrypt_strerror - undef param failure");
$errstr = mcrypt_strerror();
ok(!$errstr, "mcrypt_strerror - no param failure");

my $has_io_handle = eval { require IO::Handle };
my $has_561       = eval { require 5.6.1      };

SKIP: {
    skip "IO::Handle required for this test", 3 unless $has_io_handle;
    skip "Version 5.6.1 required for this test", 3 unless $has_561;

    $errstr = trap_stderr(sub { mcrypt_perror(-1) });
    is($errstr, "Unknown error.\n", "mcrypt_perror - success");

    local $^W = 0;
    $errstr = trap_stderr(sub { mcrypt_perror(undef) });
    ok(!$errstr, "mcrypt_perror - undef param failure");

    $errstr = trap_stderr(sub { mcrypt_perror() });
    ok(!$errstr, "mcrypt_perror - no param failure");
};

sub trap_stderr {
    my ($sub) = @_;

    # temporarily replace STDERR
    open( SAVED_STDERR, ">&STDERR" ) or die "can't dup stderr: $!";
    print SAVED_STDERR "foo" if 0;
    open( ERR_FILE, "+>", undef) or die "can't create file: $!";
    STDERR->fdopen(fileno(ERR_FILE), "w") || die "can't fdopen: $!";

    eval { &$sub };
    my $ex = $@;

    # restore STDERR
    open( STDERR, ">&SAVED_STDERR" ) or die "can't dup saved: $!";
    if ($ex) { die "$ex\n" }

    # read saved contents
    seek(ERR_FILE, 0, 0) || die "can't seek: $!";
    my $contents = '';
    1 while read(ERR_FILE, $contents, 4096, length $contents);

    close(ERR_FILE) || die "can't close: $!";

    return $contents;
}

__END__

    mcrypt_perror
