#!/usr/bin/env perl
use Test::More tests => 2;
use Crypt::Mcrypt;

#
# Verify the module loaded.  Having got this far means it did.
#
ok(1, "loaded module");

#
# Verify the XS code bootstrapped.
#
ok(defined &Crypt::Mcrypt::API::LIBMCRYPT_VERSION, "bootstrapped");

1;
