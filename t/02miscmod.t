#!/usr/bin/env perl
#
# 02miscmod.t
#
# Test miscellaneous module functions.
#
# Philip Garrett <cpan@pgarrett.net>
#
use strict;
use Test::More tests => 22;
use Crypt::Mcrypt::API qw(:all);


my ($ret,@ret);

$ret = mcrypt_module_self_test('twofish');
ok($ret == 0, 'mcrypt_module_self_test success');

$ret = mcrypt_module_self_test('no-such-algo');
ok($ret != 0, 'mcrypt_module_self_test failure');

$ret = mcrypt_module_self_test();
ok($ret != 0, 'mcrypt_module_self_test no arg failure');


$ret = mcrypt_module_is_block_algorithm('tripledes');
ok($ret == 1, 'mcrypt_module_is_block_algorithm - yes');

$ret = mcrypt_module_is_block_algorithm('arcfour');
ok($ret == 0, 'mcrypt_module_is_block_algorithm - no');

$ret = mcrypt_module_is_block_algorithm();
ok($ret != 0 && $ret != 1, 'mcrypt_module_is_block_algorithm - failure');


$ret = mcrypt_module_is_block_algorithm_mode('cbc');
ok($ret == 1, 'mcrypt_module_is_block_algorithm_mode - yes');

$ret = mcrypt_module_is_block_algorithm_mode('stream');
ok($ret == 0, 'mcrypt_module_is_block_algorifhm_mode - no');

$ret = mcrypt_module_is_block_algorithm_mode();
ok($ret != 0 && $ret != 1, 'mcrypt_module_is_block_algorithm_mode - failure');


$ret = mcrypt_module_is_block_mode('cbc');
ok($ret == 1, 'mcrypt_module_is_block_mode - yes');

$ret = mcrypt_module_is_block_mode('stream');
ok($ret == 0, 'mcrypt_module_is_block_mode - no');

$ret = mcrypt_module_is_block_mode();
ok($ret != 0 && $ret != 1, 'mcrypt_module_is_block_mode - failure');


$ret = mcrypt_module_get_algo_key_size('tripledes');
ok($ret == 24, 'mcrypt_module_get_algo_key_size - success');

$ret = mcrypt_module_get_algo_key_size();
ok($ret == -1, 'mcrypt_module_get_algo_key_size - failure');


@ret = mcrypt_module_get_algo_supported_key_sizes('tripledes');
ok("@ret" eq '24',
    'mcrypt_module_get_algo_supported_key_sizes - single size');

@ret = mcrypt_module_get_algo_supported_key_sizes('enigma');
ok("@ret" eq "@{[1..13]}",
    'mcrypt_module_get_algo_supported_key_sizes - sequence');

@ret = mcrypt_module_get_algo_supported_key_sizes('serpent');
ok("@ret" eq "16 24 32",
    'mcrypt_module_get_algo_supported_key_sizes - static list');

@ret = mcrypt_module_get_algo_supported_key_sizes();
ok(@ret == 0,
    'mcrypt_module_get_algo_supported_key_sizes - failure');


$ret = mcrypt_module_algorithm_version('tripledes');
ok(defined($ret), 'mcrypt_module_algorithm_version - success');

$ret = mcrypt_module_algorithm_version();
ok($ret <= 0, 'mcrypt_module_algorithm_version - failure');


$ret = mcrypt_module_mode_version('cbc');
ok(defined($ret), 'mcrypt_module_mode_version - success');

$ret = mcrypt_module_mode_version();
ok($ret <= 0, 'mcrypt_module_mode_version - failure');


