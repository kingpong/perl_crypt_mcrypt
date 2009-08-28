#!/usr/bin/env perl
#
# 04crypto.t
#
# Test mcrypt cryptographic functions.
#
# Philip Garrett <cpan@pgarrett.net>
#
use strict;
use Test::More tests => 17;
use Crypt::Mcrypt::API qw(:all);

#
# Note, this is just an API exerciser -- actual correctness of encryption
# and decryption is tested in 20brute.t.
#

my $ret;
my $td = mcrypt_module_open('twofish',undef,'cbc',undef);

$ret = mcrypt_generic_init(undef,undef,undef);
ok($ret < 0, "mcrypt_generic_init - undef params failure");
$ret = mcrypt_generic_init();
ok($ret < 0, "mcrypt_generic_init - no params failure");

my $key_size   = mcrypt_module_get_algo_key_size('twofish');
my $iv_size    = mcrypt_enc_get_iv_size($td);
my $block_size = mcrypt_enc_get_block_size($td);

my $key   = 'x' x $key_size;
my $iv    = 'x' x $iv_size;
my $block = 'x' x $block_size;

$ret = mcrypt_generic_init($td, $key, $iv);
is($ret, 0, "mcrypt_generic_init - success");

my $ciphertext = mcrypt_generic($td, $block);
ok(defined($ciphertext), "mcrypt_generic - defined output");
ok(length($ciphertext), "mcrypt_generic - non-empty output");

$ciphertext = mcrypt_generic(undef,undef);
ok(!defined($ciphertext), "mcrypt_generic - undef params failure");
$ciphertext = mcrypt_generic();
ok(!defined($ciphertext), "mcrypt_generic - no params failure");

my $plaintext = mdecrypt_generic($td, $block);
ok(defined($plaintext), "mdecrypt_generic - defined output");
ok(length($plaintext), "mdecrypt_generic - non-empty output");

$plaintext = mdecrypt_generic(undef,undef);
ok(!defined($plaintext), "mdecrypt_generic - undef params failure");
$plaintext = mdecrypt_generic();
ok(!defined($plaintext), "mdecrypt_generic - no params failure");

$ret = mcrypt_generic_deinit($td);
ok($ret == 0, "mcrypt_generic_deinit - success");
$ret = mcrypt_generic_deinit(undef);
ok($ret < 0, "mcrypt_generic_deinit - undef param failure");
$ret = mcrypt_generic_deinit();
ok($ret < 0, "mcrypt_generic_deinit - no param failure");

$ret = mcrypt_generic_end($td);
ok($ret == 0, "mcrypt_generic_end - success");
$ret = mcrypt_generic_end(undef);
ok($ret < 0, "mcrypt_generic_end - undef param failure");
$ret = mcrypt_generic_end();
ok($ret < 0, "mcrypt_generic_end - no param failure");

