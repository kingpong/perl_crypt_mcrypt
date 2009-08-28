#!/usr/bin/env perl
#
# 01openclose.t
#
# Test libmcrypt module opening and closing.
#
# Philip Garrett <cpan@pgarrett.net>
#
use strict;
use Test::More tests => 10;
use Crypt::Mcrypt::API qw(:all);

my $td;
my $ret;

#
# test intentional failures return the expected
#
$td = mcrypt_module_open();
ok(!$td, 'mcrypt_module_open no args failed');

$td = mcrypt_module_open('twofish');
ok(!$td, 'mcrypt_module_open no mode failed');

$td = mcrypt_module_open(undef,undef,'cfb',undef);
ok(!$td, 'mcrypt_module_open no algo failed');

$td = mcrypt_module_open('no-such-algo',undef,'cfb',undef);
ok(!$td, 'mcrypt_module_open invalid algo failed');

$td = mcrypt_module_open('twofish',undef,'no-such-mode',undef);
ok(!$td, 'mcrypt_module_open invalid mode failed');

$ret = mcrypt_module_close(undef);
ok($ret != 0, 'mcrypt_module_close null td failed');

$ret = eval { mcrypt_module_close($ret) };
ok($ret != 0, 'mcrypt_module_close bad handle failed');

#
# test successes
#
$td = mcrypt_module_open('twofish',undef,'cfb',undef);
ok($td, 'mcrypt_module_open success');
is(ref($td), 'Crypt::Mcrypt::Handle', 'mcrypt_module_open retval is blessed');

$ret = mcrypt_module_close($td);
is($ret, 0, 'mcrypt_module_close success');
undef $td;
