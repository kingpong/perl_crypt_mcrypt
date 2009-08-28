package Crypt::Mcrypt::API;
use 5.00503;
use strict;
use Exporter;

use Crypt::Mcrypt ();   # bootstrap

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION = '0.01';

@ISA = qw(Exporter);

# no exports by default.
@EXPORT = ();

# every function or macro defined by libmcrypt
@EXPORT_OK = qw(
    mcrypt_module_open
    mcrypt_module_close
    mcrypt_module_support_dynamic
    mcrypt_generic_init
    mcrypt_generic_deinit
    mcrypt_generic_end
    mdecrypt_generic
    mcrypt_generic
    mcrypt_enc_get_state
    mcrypt_enc_set_state
    mcrypt_enc_self_test
    mcrypt_enc_get_block_size
    mcrypt_enc_get_iv_size
    mcrypt_enc_get_key_size
    mcrypt_enc_is_block_algorithm
    mcrypt_enc_is_block_mode
    mcrypt_enc_is_block_algorithm_mode
    mcrypt_enc_mode_has_iv
    mcrypt_enc_get_algorithms_name
    mcrypt_enc_get_modes_name
    mcrypt_enc_get_supported_key_sizes
    mcrypt_list_algorithms
    mcrypt_list_modes
    mcrypt_perror
    mcrypt_strerror
    mcrypt_module_self_test
    mcrypt_module_is_block_algorithm
    mcrypt_module_is_block_algorithm_mode
    mcrypt_module_is_block_mode
    mcrypt_module_get_algo_key_size
    mcrypt_module_get_algo_block_size
    mcrypt_module_get_algo_supported_key_sizes
    mcrypt_module_algorithm_version
    mcrypt_module_mode_version
    mcrypt_check_version
    LIBMCRYPT_VERSION
    MCRYPT_3DES
    MCRYPT_3WAY
    MCRYPT_API_VERSION
    MCRYPT_ARCFOUR
    MCRYPT_BLOWFISH
    MCRYPT_CAST_128
    MCRYPT_CAST_256
    MCRYPT_CBC
    MCRYPT_CFB
    MCRYPT_DES
    MCRYPT_ECB
    MCRYPT_ENIGMA
    MCRYPT_FAILED
    MCRYPT_GOST
    MCRYPT_LOKI97
    MCRYPT_OFB
    MCRYPT_RC2
    MCRYPT_RIJNDAEL_128
    MCRYPT_RIJNDAEL_192
    MCRYPT_RIJNDAEL_256
    MCRYPT_SAFERPLUS
    MCRYPT_SAFER_SK128
    MCRYPT_SAFER_SK64
    MCRYPT_SERPENT
    MCRYPT_STREAM
    MCRYPT_TWOFISH
    MCRYPT_WAKE
    MCRYPT_XTEA
    MCRYPT_nOFB
);

%EXPORT_TAGS = ( 'all' => \@EXPORT_OK );

#
# These functions make the XS code a little easier by forcing exactly
# the right number of arguments.
#
my %wrappers = (
#   METHOD_NAME                                => NUMBER_OF_PARAMS
    mcrypt_list_algorithms                     => 1,
    mcrypt_list_modes                          => 1,
    mcrypt_module_open                         => 4,
    mcrypt_module_self_test                    => 2,
    mcrypt_module_is_block_algorithm           => 2,
    mcrypt_module_is_block_algorithm_mode      => 2,
    mcrypt_module_is_block_mode                => 2,
    mcrypt_module_get_algo_key_size            => 2,
    mcrypt_module_get_algo_block_size          => 2,
    mcrypt_module_get_algo_supported_key_sizes => 2,
    mcrypt_module_algorithm_version            => 2,
    mcrypt_module_mode_version                 => 2,
    mcrypt_enc_self_test                       => 1,
    mcrypt_enc_get_block_size                  => 1,
    mcrypt_enc_get_iv_size                     => 1,
    mcrypt_enc_get_key_size                    => 1,
    mcrypt_enc_is_block_algorithm              => 1,
    mcrypt_enc_is_block_mode                   => 1,
    mcrypt_enc_is_block_algorithm_mode         => 1,
    mcrypt_enc_mode_has_iv                     => 1,
    mcrypt_enc_get_algorithms_name             => 1,
    mcrypt_enc_get_modes_name                  => 1,
    mcrypt_enc_get_supported_key_sizes         => 1,
    mcrypt_enc_get_state                       => 1,
    mcrypt_enc_set_state                       => 2,
    mcrypt_generic_init                        => 3,
    mcrypt_generic_deinit                      => 1,
    mcrypt_generic_end                         => 1,
    mcrypt_generic                             => 2,
    mdecrypt_generic                           => 2,
    mcrypt_check_version                       => 1,
    mcrypt_strerror                            => 1,
    mcrypt_perror                              => 1,
);

while (my ($func_name,$n_params) = each %wrappers) {
    my $fqn  = sprintf("%s::%s", __PACKAGE__, $func_name);
    my $xsub = sprintf("%s::_%s", __PACKAGE__, $func_name);

    if (!defined &$xsub) {
        my $msg = sprintf("XSUB %s is missing (%s internal error)",
            $xsub, __PACKAGE__);
        warn $msg;
        next;
    }
    my $xsub_ref = \&{$xsub};

    no strict 'refs';
    *{$fqn} = sub {
        return $xsub_ref->(@_[0..($n_params-1)])
    };
}


1;

__END__

=head1 NAME

Crypt::Mcrypt::API - Perl interface to the libmcrypt C API

=head1 SYNOPSIS

  use Crypt::Mcrypt::API qw(:all);

  # create an encryption descriptor ("td" is mcrypt convention)
  my $td = mcrypt_open_module("twofish",undef,"cfb",undef);

  # set up an encryption key - for testing purposes only
  my $key_size = mcrypt_module_get_algo_key_size("twofish");
  my $key = pack('C*', map { int rand(256) } (1..$key_size));

  # set up an initialization vector
  my $iv_size = mcrypt_enc_get_iv_size($td);
  my $iv = pack('C*', map { int rand(256) } (1..$iv_size));

  my $err = mcrypt_generic_init($td,$key,$iv);
  if ($err != 0) {
      die mcrypt_strerror($err);
  }

  # cfb mode takes one byte at a time
  my ($in_byte,$out_byte);
  while ( read(STDIN, $in_byte, 1) ) {
        # encrypt the data
        $out_byte = mcrypt_generic($td,$in_byte);

        # or, if you'd rather decrypt:
        # $out_byte = mdecrypt_generic($td,$in_byte);

        print $out_byte;
  }

  # terminate encryption/decryption and clear buffers 
  mcrypt_generic_deinit($td);

  # finish up
  mcrypt_module_close($td);

=head1 DESCRIPTION

Crypt::Mcrypt::API is a Perl interface to Nikos Mavroyanopoulos's
libmcrypt C encryption library. Libmcrypt provides encryption and
decryption functions. It supports many encryption algorithms, including
SERPENT, RIJNDAEL, 3DES, GOST, SAFER+, CAST-256, RC2, XTEA, 3WAY,
TWOFISH, BLOWFISH, ARCFOUR, and WAKE; and several modes, including OFB,
CBC, ECB, nOFB, nCFB and CFB.

This module attempts to provide the exact same interface as the C
library, so I have omitted functional specifics here. This documentation
is generally only a guide to calling conventions. See mcrypt(3) for
functional specifications.

This is a procedural interface.  You should really only use it if you know
what you're doing *and* the object-oriented interface of L<Crypt::Mcrypt>
doesn't have what you need.  (If that's you, please let me know what I
missed!)

=head2 Exports

None by default.

Any (documented) function in this module is exportable.  You can import
the ones you need individually by name:

  use Crypt::Mcrypt::API qw(mcrypt_list_algorithms);

Or, you can import them all:

  use Crypt::Mcrypt::API qw(:all);

=head2 Constants

This module provides the following constants:

=over 4

=item LIBMCRYPT_VERSION

=item MCRYPT_3DES

=item MCRYPT_3WAY

=item MCRYPT_API_VERSION

=item MCRYPT_ARCFOUR

=item MCRYPT_BLOWFISH

=item MCRYPT_CAST_128

=item MCRYPT_CAST_256

=item MCRYPT_CBC

=item MCRYPT_CFB

=item MCRYPT_DES

=item MCRYPT_ECB

=item MCRYPT_ENIGMA

=item MCRYPT_FAILED

=item MCRYPT_GOST

=item MCRYPT_LOKI97

=item MCRYPT_OFB

=item MCRYPT_RC2

=item MCRYPT_RIJNDAEL_128

=item MCRYPT_RIJNDAEL_192

=item MCRYPT_RIJNDAEL_256

=item MCRYPT_SAFERPLUS

=item MCRYPT_SAFER_SK128

=item MCRYPT_SAFER_SK64

=item MCRYPT_SERPENT

=item MCRYPT_STREAM

=item MCRYPT_TWOFISH

=item MCRYPT_WAKE

=item MCRYPT_XTEA

=item MCRYPT_nOFB

=back

=head2 Functions

=over 4

=item mcrypt_module_open( ALGO, ALGODIR, MODE, MODEDIR )

Opens an encryption descriptor.  On success, returns the encryption
descriptor (conventionally called $td).  On failure, returns undef.

=item mcrypt_module_close( TD )

Closes an encryption descriptor TD previously opened with mcrypt_module_open.
On success, returns 0.  On failure, returns -1.

=item mcrypt_generic_init( TD, KEY, IV )

Initializes buffers for the specified encryption descriptor TD.  Returns zero
on success.  All other values indicate error.

=item mcrypt_generic( TD, PLAINTEXT )

Encrypts the text in PLAINTEXT using the encryption descriptor TD and
returns the cipher text. Returns undef on failure.

=item mdecrypt_generic( TD, CIPHERTEXT )

Decrypts the text in CIPHERTEXT using the encryption descriptor TD and
returns the plain text. Returns undef on failure.

=item mcrypt_generic_deinit( TD )

Terminates encryption with the specified encryption descriptor TD and
clears internal buffers. Returns a negative value on error.

=item mcrypt_generic_end( TD )

This function terminates encryption specified by the encryption
descriptor (TD). Actually it clears all buffers, and closes all
the modules used. Returns a negative value on error. This function
is deprecated. Use mcrypt_generic_deinit() and
mcrypt_module_close() instead.

=item mcrypt_enc_get_state( TD )

Returns a scalar containing the internal state of the algorithm
specified in the encryption descriptor TD. Returns undef on failure.

=item mcrypt_enc_set_state( TD, STATE )

Sets the internal state of the algorithm in the encryption descriptor
TD. Returns zero on success, undef on failure.

=item mcrypt_enc_self_test( TD )

Runs a self test on the algorithm specified by the encryption descriptor
TD. Returns zero on success, nonzero on failure.

=item mcrypt_enc_get_block_size( TD )

Returns the block size of the algorithm specified by the encryption
descriptor TD.

=item mcrypt_enc_get_iv_size( TD )

Returns the size of the initialization vector (IV) of the algorithm
specified in the encryption descriptor TD.  If it is 0 then the IV is
ignored in that algorithm.

=item mcrypt_enc_get_key_size( TD )

Returns the maximum key size of the algorithm specified in the encryption
descriptor TD.

=item mcrypt_enc_is_block_algorithm( TD )

Returns 1 if the algorithm specified in the encryption descriptor TD is
a block algorithm or 0 if it is a stream algorithm.

=item mcrypt_enc_is_block_mode( TD )

Returns 1 if the mode specified in the encryption descriptor TD outputs
blocks of bytes, or 0 if it outputs individual bytes.

=item mcrypt_enc_is_block_algorithm_mode( TD )

Returns 1 if the mode specified in the encryption descriptor TD is for use
with block algorithms, otherwise returns 0.

=item mcrypt_enc_mode_has_iv( TD )

Returns 1 if the mode specified in the encryption descriptor TD needs an
initialization vector (IV), otherwise returns 0.  Some "stream" algorithms
may need an IV even if the mode itself does not need an IV.

=item mcrypt_enc_get_algorithms_name( TD )

Returns a scalar containing the name of the algorithm specified in the
encryption descriptor TD. N.B. This is formatted for human consumption,
not consumption by libmcrypt (and you can't use it as an algorithm name
in mcrypt_module_*).

=item mcrypt_enc_get_modes_name( TD )

Returns a scalar containing the name of the mode specified in the
encryption descriptor TD.  N.B. This is formatted for human consumption,
not consumption by libmcrypt (and you can't use it as a mode name in
mcrypt_module_*).

=item mcrypt_enc_get_supported_key_sizes( TD )

Returns a list containing all key sizes (in bytes) supported by the
algorithm specified in the encryption descriptor TD.

=item mcrypt_list_algorithms()

=item mcrypt_list_algorithms( LIBDIR )

Returns a list containing the names of all the algorithms located in
LIBDIR. If you omit LIBDIR, the default directory is used. These
algorithms are suitable for use with mcrypt_module_*, as opposed to the
output of mcrypt_enc_get_algorithms_name().

=item mcrypt_list_modes()

=item mcrypt_list_modes( LIBDIR )

Returns a list containing the names of all the modes located in LIBDIR.
If you omit LIBDIR, the default directory is used. These modes are
suitable for use with mcrypt_module_*, as opposed to the output of
mcrypt_enc_get_modes_name().

=item mcrypt_perror( ERRNO )

Prints a human readable description of the error ERRNO to STDERR.  ERRNO
should be a value returned by mcrypt_generic_init().

=item mcrypt_strerror( ERRNO )

Returns a scalar containing the description of the error ERRNO in STDERR.
ERRNO should be a value returned by mcrypt_generic_init().

=item mcrypt_module_self_test( ALGO )

=item mcrypt_module_self_test( ALGO, ALGODIR )

Performs a self test on the algorithm ALGO located in ALGODIR (or in the
default directory if ALGODIR is omitted or undefined).  Returns 0 on
success, nonzero otherwise.

=item mcrypt_module_is_block_algorithm( ALGO )

=item mcrypt_module_is_block_algorithm( ALGO, ALGODIR )

Returns 1 if the algorithm ALGO located in ALGODIR (or in the default
directory if ALGODIR is omitted or undefined) is a block algorithm, or 0 if
it is a stream algorithm.

=item mcrypt_module_is_block_algorithm_mode( MODE )

=item mcrypt_module_is_block_algorithm_mode( MODE, MODEDIR )

Returns 1 if the mode MODE located in MODEDIR (or in the default
directory if MODEDIR is omitted or undefined) is for use with block
algorithms, otherwise 0.

=item mcrypt_module_is_block_mode( MODE )

=item mcrypt_module_is_block_mode( MODE, MODEDIR )

Returns 1 if the mode MODE located in MODEDIR (or in the default
directory if MODEDIR is omitted or undefined) outputs blocks of bytes,
or 0 if it outputs individual bytes.

=item mcrypt_module_get_algo_key_size( ALGO )

=item mcrypt_module_get_algo_key_size( ALGO, ALGODIR )

Returns the maximum key size (in bytes) of the algorithm ALGO located in
ALGODIR (or in the default directory if ALGODIR is omitted or
undefined).

=item mcrypt_module_get_algo_block_size( ALGO )

=item mcrypt_module_get_algo_block_size( ALGO, ALGODIR )

Returns the block size (in bytes) of the algorithm ALGO located in
ALGODIR (or in the default directory if ALGODIR is omitted or
undefined).

=item mcrypt_module_get_supported_key_sizes( ALGO )

=item mcrypt_module_get_supported_key_sizes( ALGO, ALGODIR )

Returns a list containing all key sizes (in bytes) supported by the
algorithm specified by ALGO located in ALGODIR (or in the default
directory if ALGODIR is omitted or undefined).

=item mcrypt_check_version()

=item mcrypt_check_version( VERSION )

Checks that the version of the library is at minimum to the requested one
and returns the current version string.  If the condition is not satisfied,
returns undef.

If you omit VERSION or it is undefined, the current version string
is returned.

=back

=head1 SEE ALSO

=over 4

=item L<Crypt::Mcrypt>

The object-oriented (much friendlier!) interface to this
API.

=item mcrypt(3)

The libmcrypt man page.

=item http://code.google.com/p/libmcrypt-perl/

This module's project home page.

=back

=head1 AUTHOR

Philip Garrett, E<lt>cpan@pgarrett.netE<gt>.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Philip Garrett.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.3 or,
at your option, any later version of Perl 5 you may have available.

=cut
