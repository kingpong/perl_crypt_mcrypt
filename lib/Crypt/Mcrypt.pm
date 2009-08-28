package Crypt::Mcrypt;
use 5.00503;
use strict;
use Carp ();
use Params::Validate ();

require DynaLoader;
use vars qw($VERSION @ISA $_API);
@ISA = qw(DynaLoader);

$VERSION = '0.01';

bootstrap Crypt::Mcrypt $VERSION;

# now, can call C api methods on $_API
$_API = bless(do { \my $dummy }, 'Crypt::Mcrypt::_APIHandle');

########################################################################
#
# Create a handy way to get at Crypt::Mcrypt::API, without either
# spelling out the package name every time, or importing its symbols
# into this package.
#
{
    package Crypt::Mcrypt::_APIHandle;
    use vars qw($AUTOLOAD);

    sub AUTOLOAD {
        no strict 'refs';   # stash access

        require Crypt::Mcrypt::API;

        my $method = substr($AUTOLOAD, rindex($AUTOLOAD, '::')+2);
        my $func   = \&{"Crypt::Mcrypt::API::$method"};

        *{$AUTOLOAD} = sub {
            shift;  # handle is junk
            return $func->(@_);
        };

        goto &$AUTOLOAD;
    }

    sub DESTROY {}  # don't autoload DESTROY
}

=head1 NAME

Crypt::Mcrypt - Object oriented interface to libmcrypt

=head1 SYNOPSIS

  use Crypt::Mcrypt;

  my $mc = Crypt::Mcrypt->new({
      algorithm => 'tripledes',
      mode      => 'cbc',
      key       => $key,
      iv        => $iv,
      padding   => 1,
  });

  # Stateless, self-contained encryption
  my $ciphertext = $mc->encrypt($plaintext);
  my $plaintext  = $mc->decrypt($ciphertext);

  # Stateful, progressive encryption
  while (read(IN, $buffer, $mc->block_size)) {
      print OUT $mc->encrypt_more($buffer); # or decrypt_more
  }
  print OUT $mc->encrypt_finish();  # or decrypt_finish

=head1 DESCRIPTION

Crypt::Mcrypt provides access to the libmcrypt library through a simple
object-oriented Perl interface.

The low-level procedural interface is available via
L<Crypt::Mcrypt::API|Crypt::Mcrypt::API>.  You should probably use this
module instead unless you know what you're doing *and* this module doesn't
provide what you need.  (If that's you, please let me know what I
missed!)

=head1 METHODS

=head2 Constructor

=over 4

=item new

  $mc = Crypt::Mcrypt->new;
  $mc = Crypt::Mcrypt->new(\%args);

Creates a new Crypt::Mcrypt object.  If \%args is provided, the object
will be initialized with its contents.

Please note that, before encrypting or decrypting, you MUST provide an
algorithm, a mode, and a key. Some configurations also require an IV.

Valid parameters in \%args are:

=over 4

=item algorithm or algo

The algorithm to be used. See mcrypt(3) for names and details of
algorithms available on your system. algo() is an alias for
algorithm().

=item mode

The mode to be used. See mcrypt(3) for names and details of modes
available on your system.

=item key

The key to use for encryption.  Consult mcrypt(3) to determine the
appropriate key size for your chosen algorithm.

=item iv

The initialization vector (IV) used to initialize the crytography
process. The IV size is usually the same as the algorithm's block size,
but if you're unsure, you can check by using the L</info> method.

=item padding

What kind of padding should be applied to the encrypted or decrypted
data in the case that the plaintext size is not an exact multiple of the
block size.

See the L</padding> method for more details.

=item algorithm_dir or algo_dir

The directory where the algorithm module resides. Usually unnecessary
unless you are providing your own algorithm module (and in that case, I
probably don't need to explain this to you). algo_dir() is an alias for
algorithm_dir().

=item mode_dir

The directory where the mode module resides. Just like algorithm_dir,
you probably don't need this unless you're providing your own mcrypt
mode module.

=back

=cut

sub new {
    my $class = shift;
    my %args  = Params::Validate::validate(@_, {
        algorithm     => { type => Params::Validate::SCALAR, optional => 1 },
        algo          => { type => Params::Validate::SCALAR, optional => 1 },
        mode          => { type => Params::Validate::SCALAR, optional => 1 },
        key           => { type => Params::Validate::SCALAR, optional => 1 },
        iv            => { type => Params::Validate::SCALAR, optional => 1 },
        padding       => { type => Params::Validate::SCALAR, optional => 1 },
        algorithm_dir => { type => Params::Validate::SCALAR, optional => 1 },
        algo_dir      => { type => Params::Validate::SCALAR, optional => 1 },
        mode_dir      => { type => Params::Validate::SCALAR, optional => 1 },
    });

    my $self = bless({}, $class);

    for my $initializer (keys %args) {
        $self->$initializer( $args{$initializer} );
    }

    return $self;
}

=back

=head2 Class Methods

These methods may be called on either a Crypt::Mcrypt object or on the
class itself.

=over 4

=item algorithms or algos

  @algorithms = Crypt::Mcrypt->algorithms;
  @algorithms = Crypt::Mcrypt->algos;
  @algorithms = $mc->algos;

Returns a list of algorithms supported by your system's libmcrypt.  algos()
is an alias for algorithms().

=cut

sub algorithms {
    return $_API->mcrypt_list_algorithms();
}

# not using a direct alias allows subclasses to alter the behavior
sub algos {
    my $invocant = shift;
    return $invocant->algorithms(@_);
}

=item modes

  @modes = Crypt::Mcrypt->modes;
  @modes = $mc->modes;

Returns a list of modes supported by your system's libmcrypt.

=cut

sub modes {
    return $_API->mcrypt_list_modes();
}

=item module_self_test

  $ok = Crypt::Mcrypt->module_self_test($module_name);
  $ok = $mc->module_self_test($module_name);

Performs a self test on the specified module and returns true if
successful, false otherwise.

=cut

sub module_self_test {
    my $invocant = shift;
    my ($module_name) = Params::Validate::validate_pos(@_, 1);

    my $ret = $_API->mcrypt_module_self_test($module_name);

    return (defined($ret) && $ret == 0);
}

=item algorithm_info

  $info = Crypt::Mcrypt->algorithm_info($algorithm_name);
  $info = $mc->algorithm_info($algorithm_name);

Returns a hash reference containing information about the specified
algorithm.  If $algorithm_name is invalid, returns undef.

$info_hash contains these keys:

=over 4

=item is_block_algorithm

Will be 1 if the algorithm is a block algorithm, 0 if it is a stream
algorithm.

=item max_key_size

The longest key size supported by the algorithm, in bytes.

=item block_size

The block size of the algorithm, in bytes.

=item version

The version number of the algorithm.

=back

=cut

sub algorithm_info {
    my $invocant = shift;
    my ($algo_name) = Params::Validate::validate_pos(@_, 1);

    my %info;

    $info{is_block_algorithm} =
        $_API->mcrypt_module_is_block_algorithm($algo_name) ? 1 : 0;

    $info{max_key_size} =
        $_API->mcrypt_module_get_algo_key_size($algo_name);

    $info{block_size} =
        $_API->mcrypt_module_get_algo_block_size($algo_name);

    $info{version} =
        $_API->mcrypt_module_algorithm_version($algo_name);

    return \%info;
}

=item mode_info

  $info = Crypt::Mcrypt->mode_info($mode_name);
  $info = $mc->mode_info($mode_name);

Returns a hash reference containing information about the specified
algorithm.  If $mode_name is invalid, returns undef.

$info_hash contains these keys:

=over 4

=item is_block_algorithm_mode

Will be 1 if the mode is for use with block algorithms, 0 otherwise.

=item is_block_mode

Will be 1 if the mode outputs blocks, or 0 if it outputs individual bytes.

=item version

The version number of the mode.

=back

=cut

sub mode_info {
    my $invocant = shift;

    my ($mode_name) = Params::Validate::validate_pos(@_, 1);

    my %info;

    $info{is_block_algorithm_mode} =
        $_API->mcrypt_module_is_block_algorithm_mode($mode_name) ? 1 : 0;

    $info{is_block_mode} =
        $_API->mcrypt_module_is_block_mode($mode_name) ? 1 : 0;

    $info{version} =
        $_API->mcrypt_module_mode_version($mode_name);

    return \%info;
}

=item version

  $version = Crypt::Mcrypt->version();
  $version = $mc->version();

Returns the libmcrypt version number.

=cut

sub version {
    return $_API->LIBMCRYPT_VERSION;
}

=item check_version

  $version = Crypt::Mcrypt->check_version($required_version);
  $version = $mc->check_version($required_version);

Checks $required_version string against the current mcrypt version.
Returns the current version if it is at least as new as $required_version.

=cut

sub check_version {
    my $invocant = shift;
    my ($req_version) = Params::Validate::validate_pos(@_, 0);
    return $_API->mcrypt_check_version($req_version);
}

=back

=head2 Instance Methods

=over 4

=item algorithm or algo

  $mc->algorithm($algorithm_name);
  $mc->algo($algorithm_name);

  $algorithm_name = $mc->algorithm;
  $algorithm_name = $mc->algo;

Gets or sets the cryptographic algorithm to be used.  Setting the algorithm
value will reset any internal state in the encryption engine. algo() is an
alias for algorithm().

=cut

sub algorithm {
    my $self = shift;
    if (@_) {
        ($self->{_algorithm}) = Params::Validate::validate_pos(@_,1);
        $self->_reset();
    }
    return $self->{_algorithm};
}

# not using a direct alias allows subclasses to alter the behavior
sub algo {
    my $self = shift;
    return $self->algorithm(@_);
}

=item mode

  $mc->mode($mode_name);

  $mode = $mc->mode;

Gets or sets the encryption mode to be used.  Setting the mode value will
reset any internal state in the encryption engine.

=cut

sub mode {
    my $self = shift;
    if (@_) {
        ($self->{_mode}) = Params::Validate::validate_pos(@_,1);
        $self->_reset();
    }
    return $self->{_mode};
}

=item key

  $mc->key($key);

  $key = $mc->key;

Sets or gets the encryption key. You MUST set the key before encrypting
or decrypting. Consult the mcrypt(3) man page to determine the
appropriate key size to use, depending on the algorithm chosen.

You can also use the L</supported_key_sizes> method to determine the
available key sizes for your configuration, e.g.

  my $mc = Crypt::Mcrypt->new({ algo => 'tripledes', mode => 'cbc' });
  my @key_sizes = $mc->supported_key_sizes();


=cut

sub key {
    my $self = shift;
    if (@_) {
        ($self->{_key}) = Params::Validate::validate_pos(@_,1);
        $self->_reset();
    }
    return $self->{_key};
}

=item iv

  $mc->iv($iv);

  $iv = $mc->iv;

Sets or gets the initialization vector (IV) used to initialize the
crytography process.  With some modes, you MUST provide an IV before
encryption or decryption.  See the mcrypt(3) man page to determine whether
this is the case.

You can also determine if an IV is required programatically, and if so,
what the size should be:

  my $mc = Crypt::Mcrypt->new({ algo => 'tripledes', mode => 'cbc' });
  my $needs_iv = $mc->info->{mode_has_iv};
  my $iv_size  = $mc->info->{iv_size};  # bytes

=cut

sub iv {
    my $self = shift;
    if (@_) {
        ($self->{_iv}) = Params::Validate::validate_pos(@_,1);
        $self->_reset();
    }
    return $self->{_iv};
}

=item padding

  $mc->padding($padding_type);

  $padding_type = $mc->padding;

Sets or gets what (if any) padding should be applied to the encrypted or
decrypted data in the case that the plaintext size is not an exact
multiple of the block size.

Changing the padding type will reset any internal state in the
encryption engine.

$padding_type may be any of:

=over 4

=item undef, 0, '' or 'none'

Any false value disables padding entirely.  This is the default.

=item "pkcs7", "pkcs5"

Padding according to PKCS#7 (or PKCS#5, depending what you read). Each
byte in the padding contains the number of padded bytes. For example, if
5 bytes are needed, each of the 5 bytes will contain the number 0x05. If
the plaintext does fall on a block boundary (where normally no padding
would be required), an entire block of padding will be added to avoid
ambiguity.

This is the recommended padding method for interoperability since it is
widely supported on other platforms.

Example for block size 8:

  Plaintext Block:  FF FF FF
     Padded Block:  FF FF FF 05 05 05 05 05

=item "zeros"

Each byte in the padding contains the value 0. This works well for null-
terminated strings but can be ambiguous when decrypting raw binary data.

=back

=cut

sub padding {
    my $self = shift;
    if (@_) {
        my ($p_type) = Params::Validate::validate_pos(@_,1);
        $self->_set_padding_type($p_type);
        $self->_reset();
    }
    return $self->{_padding};
}

=item algorithm_dir or algo_dir

  $mc->algorithm_dir($algorithm_dir);
  $mc->algo_dir($algorithm_dir);

  $algorithm_dir = $mc->algorithm_dir;
  $algorithm_dir = $mc->algo_dir;

Sets or gets the directory where the algorithm module resides. Usually
unnecessary unless you are providing your own algorithm module (and in
that case, I probably don't need to explain this to you). algo_dir() is
an alias for algorithm_dir().

=cut

sub algorithm_dir {
    my $self = shift;
    if (@_) {
        ($self->{_algorithm_dir}) = Params::Validate::validate_pos(@_,1);
        $self->_reset();
    }
    return $self->{_algorithm_dir};
}

sub algo_dir {
    my $self = shift;
    return $self->algorithm_dir(@_);
}

=item mode_dir

  $mc->mode_dir($mode_dir);

  $mode_dir = $mc->mode_dir;

Sets or gets the directory where the mode module resides. Just like
algorithm_dir, you probably don't need this unless you're providing
your own mcrypt mode module.

=cut

sub mode_dir {
    my $self = shift;
    if (@_) {
        ($self->{_mode_dir}) = Params::Validate::validate_pos(@_,1);
        $self->_reset();
    }
    return $self->{_mode_dir};
}

=item errcode

  $err_code = $mc->errcode;

Returns the last error code generated by an internal call to
mcrypt_generic_init.

=cut

sub errcode {
    my $self = shift;
    if (@_) {
        ($self->{_errcode}) = Params::Validate::validate_pos(@_,1);
    }
    return $self->{_errcode};
}

=item errstr

  $err_str = $mc->errstr;

Returns a textual description of the last error code generated by an
internal call to mcrypt_generic_init.

=cut

sub errstr {
    my ($self) = @_;
    return defined $self->errcode
        ? $_API->mcrypt_strerror($self->errcode)
        : undef;
}

=item supported_key_sizes

  @key_sizes = $mc->supported_key_sizes;

Returns a list containing the supported key sizes (in bytes) of the current algorithm.

=cut

sub supported_key_sizes {
    my ($self) = @_;
    my $td = $self->_get_opened_td || return;
    return $_API->mcrypt_enc_get_supported_key_sizes($td);
}

=item encrypt

  $ciphertext = $mc->encrypt($plaintext);
  $ciphertext = $mc->encrypt(\$plaintext);

Encrypts the data in $plaintext and returns the encrypted text as a
scalar. The length of data $plaintext should be a multiple of the
algorithm's block size if a block cipher is used.

On failure, returns undef.

=cut

sub encrypt {
    my $self = shift;
    my ($plain_text) = Params::Validate::validate_pos(@_,1);

    # make sure we have a freshly initialized TD
    $self->_reset_if_active();

    my $cipher_text = $self->encrypt_more($plain_text);
    if (not defined $cipher_text) {
        return undef;
    }
    $cipher_text .= $self->encrypt_finish();

    return $cipher_text;
}

=item decrypt

  $plaintext = $mc->decrypt($ciphertext);
  $plaintext = $mc->decrypt(\$ciphertext);

Decrypts the data in $ciphertext and returns the decrypted text as a
scalar.  The length of data in $ciphertext should be a multiple of the
algorithm's block size if a block cipher is used.

=cut

sub decrypt {
    my $self = shift;
    my ($cipher_text) = Params::Validate::validate_pos(@_,1);

    # make sure we have a freshly initialized TD
    $self->_reset_if_active();

    my $plain_text = $self->decrypt_more($cipher_text);
    if (not defined $plain_text) {
        return undef;
    }
    $plain_text .= $self->decrypt_finish();

    return $plain_text;
}

=item reset

  $mc->reset();

Resets and initializes the internal encryption engine with the current
key and IV. You will generally only need this if you plan to use
encrypt_more or decrypt_more and you plan to encrypt or decrypt more
than one item with the same key and IV.

=cut

sub reset {
    my $self = shift;

    $self->_reset();

    # maybe add re-init here later to generate any exceptions here rather
    # than during encryption?

    return;
}

=item encrypt_more

  $ciphertext_chunk = $mc->encrypt_more($plaintext_chunk);

Encrypts the data in $block and returns the ciphertext as a scalar.
Unlike C<encrypt>, this method does not reset the internal algorithm
state, so it can be used to encrypt a large document in smaller chunks.

Plaintext input to this function will be buffered across calls until it
is large enough to fill a complete block, at which point the encrypted
data will be returned. That means this method might sometimes return an
empty string, even when $plaintext is not empty.

After you have finished processing the plaintext in chunks, you should call
L</encrypt_finish> to get the final block.

=cut

sub encrypt_more {
    my $self = shift;
    my ($plain_text) = Params::Validate::validate_pos(@_,1);

    if (not defined $plain_text) {
        $plain_text = '';
    }

    $self->_note_activity();

    my $td = $self->_get_cryptable_td() || return undef;

    if ($self->info->{is_block_mode}) {
        $self->{_pt_buffer} .= $plain_text;

        my $buf_length = length($self->{_pt_buffer});
        my $blk_size   = $self->info->{block_size};
        my $n_blocks   = int($buf_length / $blk_size);

        if ($n_blocks > 0) {
            my $cipher_text = $_API->mcrypt_generic($td,
                substr($self->{_pt_buffer}, 0, $n_blocks*$blk_size));

            # move the unencrypted part to the top of the buffer
            $self->{_pt_buffer} = substr($self->{_pt_buffer}, $n_blocks*$blk_size);

            return $cipher_text;
        }
        else {
            # just buffer for now
            return '';
        }
    }
    else {
        # operating in stream mode, no padding or buffering
        return $_API->mcrypt_generic($td, $plain_text);
    }
}

=item encrypt_finish

  $ciphertext .= $mc->encrypt_finish();

Returns the final ciphertext chunk for the encrypted stream.  Padding is
applied in this step.

=cut

sub encrypt_finish {
    my ($self) = @_;

    $self->_note_activity();

    my $td = $self->_get_cryptable_td() || return undef;

    unless ($self->info->{is_block_mode}) {
        # no buffering or padding in stream mode
        return '';
    }

    my $buf_length = length($self->{_pt_buffer});
    my $blk_size   = $self->info->{block_size};
    my $padding    = $self->padding || '';

    if ($buf_length > $blk_size) {
        die "internal error: buffer larger than block size";
    }

    if ($buf_length == 0 && !$padding) {
        # nothing to encrypt, no padding to add
        return '';
    }
    elsif ($buf_length == 0 && $padding eq 'zeros') {
        # no padding necessary
        return '';
    }

    my $pad_size = $blk_size - $buf_length;

    if ($padding eq 'pkcs7') {
        $pad_size = $blk_size if $pad_size == 0;
        $self->{_pt_buffer} .= chr($pad_size) x $pad_size;
    }
    elsif ($padding eq 'zeros') {
        $self->{_pt_buffer} .= chr(0) x $pad_size;
    }

    my $cipher_text = $_API->mcrypt_generic($td, $self->{_pt_buffer});
    delete $self->{_pt_buffer};

    return $cipher_text;
}

=item decrypt_more

  $plaintext = $mc->decrypt_more($ciphertext);

Decrypts the data in $ciphertext and returns the plaintext as a scalar.
Unlike C<decrypt>, this method does not reset the internal algorithm
state, so it can be used to decrypt a large document in smaller chunks.

Ciphertext input to this function will be buffered across calls until it
is large enough to fill a complete block, at which point the decrypted
data will be returned. That means this method might sometimes return an
empty string, even when $ciphertext is not empty.

After you have finished processing the ciphertext in chunks, you should
call L</decrypt_finish> to get the final block.

=cut

sub decrypt_more {
    my $self = shift;
    my ($cipher_text) = Params::Validate::validate_pos(@_,1);

    if (not defined $cipher_text) {
        $cipher_text = '';
    }

    $self->_note_activity();

    my $td = $self->_get_cryptable_td() || return undef;

    if ($self->info->{is_block_mode}) {
        $self->{_ct_buffer} .= $cipher_text;

        my $buf_length = length($self->{_ct_buffer});
        my $blk_size   = $self->info->{block_size};
        my $n_blocks   = int($buf_length / $blk_size);

        if ($n_blocks > 0) {
            my $plain_text = $_API->mdecrypt_generic($td,
                substr($self->{_ct_buffer}, 0, $n_blocks*$blk_size));

            # move the unencrypted part to the top of the buffer
            $self->{_ct_buffer} = substr($self->{_ct_buffer},
                $n_blocks*$blk_size);

            return $plain_text;
        }
        else {
            # just buffer for now
            return '';
        }
    }
    else {
        # no buffering or padding in stream mode
        return $_API->mdecrypt_generic($td, $cipher_text);
    }
}

=item decrypt_finish

  $ciphertext .= $mc->decrypt_finish();

Returns the final plaintext chunk for the decrypted stream.  Padding is
removed in this step.

=cut

sub decrypt_finish {
    my ($self) = @_;

    $self->_note_activity();

    my $td = $self->_get_cryptable_td() || return undef;

    unless ($self->info->{is_block_mode}) {
        return '';
    }

    my $buf_length = length($self->{_ct_buffer});
    my $blk_size   = $self->info->{block_size};
    my $padding    = $self->padding || '';

    if ($buf_length > $blk_size) {
        die "internal error: buffer larger than block size";
    }
    if (($buf_length % $blk_size)!=0) {
        warn "ciphertext length is not a multiple of the block size, "
           . "continuing anyway";
    }
    if (!$padding && !$buf_length) {
        return '';
    }

    my $cipher_text = $_API->mdecrypt_generic($td, $self->{_ct_buffer});
    
    if ($padding eq 'pkcs7') {
    }
    elsif ($padding eq 'zeros') {
    }

    delete $self->{_pt_buffer};

    return $cipher_text;
}

=item self_test

  $ok = $mc->self_test;

Performs the algorithm internal self test and returns true if it succeeds,
false otherwise.

=cut

sub self_test {
    my ($self) = @_;
    my $td = $self->_get_opened_td || return undef;

    # zero on success
    my $ret = $_API->mcrypt_enc_self_test($td);

    return defined($ret) && $ret == 0;
}

=item info

  $info_hash = $mc->info;

Returns a hash reference containing information about the current algorithm
and mode.

$info_hash contains these keys:

=over 4

=item block_size

The block size of the algorithm, in bytes.

=item iv_size

The size of the initialization vector (IV) of the algorithm, in bytes.

=item max_key_size

The longest key size supported by the algorithm, in bytes.

To help those who are familiar with the libmcrypt API, this value is also
available under the key 'key_size'.

=item is_block_algorithm

Will be 1 if the algorithm is a block algorithm, 0 if it is a stream
algorithm.

=item is_block_mode

Will be 1 if the mode outputs blocks, or 0 if it outputs individual bytes.

=item is_block_algorithm_mode

Will be 1 if the mode is for use with block algorithms, otherwise 0.

=item mode_has_iv

Will be 1 if the mode requires an IV, 0 otherwise. Some 'stream'
algorithms may need an IV even if the mode itself does not
require an IV.

=item algorithm_name

Returns a friendly name for the algorithm being used, e.g. if you
specified "twofish" as the algorithm, this would return "Twofish".

To help those who are familiar with the libmcrypt API, this value is
also available under the key 'algorithms_name'.

=item mode_name

Returns a friendly name for the mode being used, e.g. if you specified
"cbc" as the mode, this would return "CBC".

To help those who are familiar with the libmcrypt API, this value is also
available under the key 'modes_name'.

=back

=cut

sub info {
    my $self = shift;
    return $self->{_info} if $self->{_info};

    my $td = $self->_get_opened_td || return undef;

    my %info;

    $info{block_size} =
        $_API->mcrypt_enc_get_block_size($td);

    $info{iv_size} =
        $_API->mcrypt_enc_get_iv_size($td);

    $info{key_size} =
        $info{max_key_size} =
            $_API->mcrypt_enc_get_key_size($td);

    $info{is_block_algorithm} =
        $_API->mcrypt_enc_is_block_algorithm($td);

    $info{is_block_mode} =
        $_API->mcrypt_enc_is_block_mode($td);

    $info{is_block_algorithm_mode} =
        $_API->mcrypt_enc_is_block_algorithm_mode($td);

    $info{mode_has_iv} =
        $_API->mcrypt_enc_mode_has_iv($td);

    $info{algorithms_name} = # yuck
        $info{algorithm_name} =
            $_API->mcrypt_enc_get_algorithms_name($td);

    $info{modes_name} = # yuck
        $info{mode_name} =
            $_API->mcrypt_enc_get_modes_name($td);

    return $self->{_info} = \%info;
}

=item get_state

  $state = $mc->get_state;

Returns a scalar containing the internal state of the algorithm, which can
be used later to restore the state.  See L</set_state>.

=cut

sub get_state {
    my $self = shift;
    my $td = $self->_get_cryptable_td() || return undef;
    return $_API->mcrypt_enc_get_state($td);
}

=item set_state

  $mc->set_state($state);

Sets the internal state of the algorithm using the data contained in
the scalar $state. $state was retrieved earlier using the
L</get_state> method.

Returns true if successful, otherwise false.

=cut

sub set_state {
    my $self = shift;
    my ($state) = Params::Validate::validate_pos(@_,1);

    my $td = $self->_get_cryptable_td() || return undef;

    # zero on success
    my $ret = $_API->mcrypt_enc_set_state($td);
    if (defined($ret) && $ret == 0) {
        return 1;
    }
    
    return undef;
}

=back

=head1 SEE ALSO

The mcrypt(3) man page.

=head1 SUPPORT

The Crypt::Mcrypt module is free software. IT COMES WITHOUT WARRANTY
OF ANY KIND.

You can email me (the author) for support, and I will attempt to help
you.

=head1 AUTHOR

Philip Garrett, E<lt>philip at pastemagazine.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2009 by Philip Garrett

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.3 or,
at your option, any later version of Perl 5 you may have available.

=cut

########################################################################
#
# PRIVATE METHODS
#

#
# $self->_note_activity();
#
# Makes a note that the current TD has been used to encrypt or decrypt, and
# therefore requires reinitialization to encrypt a new document.
#
sub _note_activity {
    my ($self) = @_;
    $self->{_activity} = 1;
    return;
}

#
# $self->_reset_if_active();
#
# Resets / reinitializes the internal TD iff it can't be used to start
# encrypting a new document, i.e. it's already been used.
#
sub _reset_if_active {
    my ($self) = @_;
    if ($self->{_activity}) {
        $self->_reset();
    }
    return;
}

#
# my $td = $self->_opened_td()
#
# Returns an encryption descriptor that is opened (i.e. configured with
# algorithm and mode) but is not guaranteed to be ready for encryption --
# use _cryptable_td() for that.
#
sub _get_opened_td {
    my ($self) = @_;
    my $td = $self->__opened_td();
    return $td if $td;

    my $algo = $self->algorithm
        || Carp::croak "Unable to open mcrypt without an algorithm.";
    my $mode = $self->mode
        || Carp::croak "Unable to open mcrypt without a mode.";

    my $adir = $self->algorithm_dir;
    my $mdir = $self->mode_dir;

    $td = $_API->mcrypt_module_open($algo,$adir,$mode,$mdir);
    if (!$td) {
        $self->errcode(-1); # "Unknown error."
        return undef;
    }

    # now that a different algo/mode is opened, old info no longer
    # necessarily applies.
    delete $self->{_info};

    return $self->__opened_td($td);
}

sub __opened_td {
    my $self = shift;
    $self->{__opened_td} = shift if @_;
    return $self->{__opened_td};
}

#
# my $td = $self->_cryptable_td()
#
# Returns an encryption descriptor configured using the object's current
# algorithm, mode, key and IV -- ready to use for encrypting/decrypting.
#
sub _get_cryptable_td {
    my ($self) = @_;
    my $td = $self->__cryptable_td();
    return $td if $td;

    $td = $self->_get_opened_td() || return undef;

    my $key = $self->key
        || Carp::croak "Unable to initialize mcrypt without a key.";
    my $iv  = $self->iv;

    # negative on error
    my $ret = $_API->mcrypt_generic_init($td, $key, $iv);

    $self->errcode($ret);

    if ($ret < 0) {
        my $str = $self->errstr;
        Carp::croak "Unable to initialize mcrypt: $str";
    }
    return $self->__cryptable_td($td);
}

sub __cryptable_td {
    my $self = shift;
    $self->{__cryptable_td} = shift if @_;
    return $self->{__cryptable_td};
}

#
# $self->_reset()
#
# Deinitializes and closes the TD if necessary.
#
sub _reset {
    my ($self) = @_;

    if (my $opened_td = $self->__opened_td) {

        # if it's opened, it might be initialized
        if (my $cryptable_td = $self->__cryptable_td) {
            # negative on error
            my $ret = $_API->mcrypt_generic_deinit($cryptable_td);
            if ($ret < 0) {
                Carp::carp "Unable to deinitialize mcrypt";
            }
            $self->__cryptable_td(undef);
        }

        # negative on error
        my $ret = $_API->mcrypt_module_close($opened_td);
        if ($ret < 0) {
            Carp::carp "Unable to close mcrypt";
        }
        $self->__opened_td(undef);
    }

    # kill any buffers we've accumulated
    delete $self->{_pt_buffer};

    # no need to reset for the next encryption
    delete $self->{_activity};

    return;
}

#
# $self->_set_padding_type($type_name)
#
# Normalizes the padding type specified in $type_name and populates
# $self->{_padding}.
#
sub _set_padding_type {
    my ($self,$input) = @_;

    my $p_type;
    if (not $input) {
        $p_type = undef;
    }
    elsif ($input eq 'none') {
        $p_type = undef;
    }
    elsif ($input eq 'pkcs7') {
        $p_type = 'pkcs7';
    }
    elsif ($input eq 'pkcs5') {
        $p_type = 'pkcs7';
    }
    elsif ($input eq 'zeros') {
        $p_type = 'zeros';
    }
    else {
        Carp::croak "unrecognized padding type '$input'";
    }

    $self->{_padding} = $p_type;
    return;
}

sub DESTROY {
    my ($self) = @_;
    $self->_reset();    # deinit and close

    for my $super (@ISA) {
        next if $self->{__DESTROYED__}{$super}++;
        if (my $destructor = $super->can('DESTROY')) {
            $destructor->(@_);
        }
    }
}

1;
