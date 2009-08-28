#!/usr/bin/env perl
#
# 03handleinfo.t
#
# Test mcrypt handle info methods.
#
# Philip Garrett <cpan@pgarrett.net>
#
use strict;
use Test::More tests => 38;
use Crypt::Mcrypt::API qw(:all);

my ($ret,@ret);

my %td;
$td{twofish} = mcrypt_module_open('twofish',undef,'cbc',undef);
$td{arcfour} = mcrypt_module_open('arcfour',undef,'stream',undef);
$td{gost}    = mcrypt_module_open('gost',undef,'ecb',undef);
$td{enigma}  = mcrypt_module_open('enigma',undef,'stream',undef);


$ret = mcrypt_enc_self_test($td{twofish});
is($ret, 0, 'mcrypt_enc_self_test success');

$ret = mcrypt_enc_self_test('');
ok($ret != 0, 'mcrypt_enc_self_test invalid but defined parameter failure');

$ret = mcrypt_enc_self_test();
ok($ret != 0, 'mcrypt_enc_self_test no arg failure');


$ret = mcrypt_enc_get_block_size($td{twofish});
is($ret, 16, 'mcrypt_enc_get_block_size success');

$ret = mcrypt_enc_get_block_size('');
ok($ret <= 0, 'mcrypt_enc_get_block_size inv but defined parameter failure');

$ret = mcrypt_enc_get_block_size();
ok($ret <= 0, 'mcrypt_enc_get_block_size no arg failure');


$ret = mcrypt_enc_get_iv_size($td{twofish});
is($ret, 16, 'mcrypt_enc_get_iv_size success');

$ret = mcrypt_enc_get_iv_size('');
ok($ret <= 0, 'mcrypt_enc_get_iv_size inv but defined parameter failure');

$ret = mcrypt_enc_get_iv_size();
ok($ret <= 0, 'mcrypt_enc_get_iv_size no arg failure');


$ret = mcrypt_enc_is_block_algorithm($td{twofish});
is($ret, 1, 'mcrypt_enc_is_block_algorithm - yes');

$ret = mcrypt_enc_is_block_algorithm($td{arcfour});
is($ret, 0, 'mcrypt_enc_is_block_algorithm - no');

$ret = mcrypt_enc_is_block_algorithm('');
is($ret, -1, 'mcrypt_enc_is_block_algorithm - inv but def failure');

$ret = mcrypt_enc_is_block_algorithm();
is($ret, -1, 'mcrypt_enc_is_block_algorithm - no args failure');


$ret = mcrypt_enc_is_block_mode($td{twofish});
is($ret, 1, 'mcrypt_enc_is_block_mode - yes');

$ret = mcrypt_enc_is_block_mode($td{arcfour});
is($ret, 0, 'mcrypt_enc_is_block_mode - no');

$ret = mcrypt_enc_is_block_mode('');
is($ret, -1, 'mcrypt_enc_is_block_mode - inv but def failure');

$ret = mcrypt_enc_is_block_mode();
is($ret, -1, 'mcrypt_enc_is_block_mode - no args failure');


$ret = mcrypt_enc_is_block_algorithm_mode($td{twofish});
is($ret, 1, 'mcrypt_enc_is_block_algorithm_mode - yes');

$ret = mcrypt_enc_is_block_algorithm_mode($td{arcfour});
is($ret, 0, 'mcrypt_enc_is_block_algorithm_mode - no');

$ret = mcrypt_enc_is_block_algorithm_mode('');
is($ret, -1, 'mcrypt_enc_is_block_algorithm_mode - inv but def failure');

$ret = mcrypt_enc_is_block_algorithm_mode();
is($ret, -1, 'mcrypt_enc_is_block_algorithm_mode - no args failure');



$ret = mcrypt_enc_mode_has_iv($td{twofish});
is($ret, 1, 'mcrypt_enc_mode_has_iv - yes');

$ret = mcrypt_enc_mode_has_iv($td{gost});
is($ret, 0, 'mcrypt_enc_mode_has_iv - no');

$ret = mcrypt_enc_mode_has_iv('');
is($ret, -1, 'mcrypt_enc_mode_has_iv - inv but def failure');

$ret = mcrypt_enc_mode_has_iv();
is($ret, -1, 'mcrypt_enc_mode_has_iv - no args failure');


$ret = mcrypt_enc_get_algorithms_name($td{twofish});
ok($ret =~ /twofish/i, 'mcrypt_enc_get_algorithms_name');

$ret = mcrypt_enc_get_algorithms_name('');
is($ret, undef, 'mcrypt_enc_get_algorithms_name - inv but def failure');

$ret = mcrypt_enc_get_algorithms_name();
is($ret, undef, 'mcrypt_enc_get_algorithms_name - no args failure');


$ret = mcrypt_enc_get_modes_name($td{twofish});
ok($ret =~ /cbc/i, 'mcrypt_enc_get_modes_name');

$ret = mcrypt_enc_get_modes_name('');
is($ret, undef, 'mcrypt_enc_get_modes_name - inv but def failure');

$ret = mcrypt_enc_get_modes_name();
is($ret, undef, 'mcrypt_enc_get_modes_name - no args failure');


@ret = mcrypt_enc_get_supported_key_sizes($td{twofish});
is("@ret", '16 24 32', 'mcrypt_enc_get_supported_key_sizes - static');

@ret = mcrypt_enc_get_supported_key_sizes($td{enigma});
is("@ret", join(" ",1..13), 'mcrypt_enc_get_supported_key_sizes - dyn');

@ret = mcrypt_enc_get_supported_key_sizes('');
is(@ret + 0, 0, 'mcrypt_enc_get_supported_key_sizes - inv but def fail');

@ret = mcrypt_enc_get_supported_key_sizes();
is(@ret + 0, 0, 'mcrypt_enc_get_supported_key_sizes - no args failure');

my ($state,$output);
my $key   = 'xxxxxxxx';
my $iv    = 'xxxxxxxx';
my $text  = 'xxxxxxxx';
{
    my $td = mcrypt_module_open('tripledes',undef,'cbc',undef);
    mcrypt_generic_init($td,$key,$iv);
    mcrypt_generic($td,$text);
    $state = mcrypt_enc_get_state($td);
    ok(defined($state), 'mcrypt_enc_get_state - defined');
    $output = mcrypt_generic($td,$text);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
}
{
    my $td = mcrypt_module_open('tripledes',undef,'cbc',undef);
    mcrypt_generic_init($td,$key,$iv);

    # note no mcrypt_generic before setting state

    $ret = mcrypt_enc_set_state($td,$state);
    ok($ret == 0, 'mcrypt_enc_set_state - success');
    my $comp = mcrypt_generic($td,$text);

    is($comp, $output, 'mcrypt_enc_set_state - output ok');

    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
}

mcrypt_module_close($_) foreach values %td;

