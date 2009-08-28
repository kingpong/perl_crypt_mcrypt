#!/usr/bin/perl
use Test::More tests => 49;
use Crypt::Mcrypt::API qw(:all);

#
# Test the libmcrypt API in the order in which it is described in the
# manpage (almost).
#

sub dump_bin {
    join(' ', map { sprintf("%02x",$_) } unpack('C*',shift));
}

# using the same algorithm as the manpage.
$td = mcrypt_module_open('twofish','','cbc','');

ok($td, "mcrypt_module_open success");
isa_ok($td, "Crypt::Mcrypt::Handle", "mcrypt handle");

$key = "0123456789012345";  # 16-byte (128-bit) key
$iv  = "0123456789012345";  # 16-byte (128-bit) IV
$ret = mcrypt_generic_init($td, $key, $iv);

ok($ret == 0, "mcrypt_generic_init success");

$plaintext = 'abcdefghijklmnop';
$ciphertext = mcrypt_generic($td, $plaintext);
$known_good = qq(d3 c0 d1 ae a9 02 be b5 53 c2 db f3 7a 09 22 ec);
is(dump_bin($ciphertext), $known_good, "mcrypt_generic success");

ok(mcrypt_generic_deinit($td)>=0, 'mcrypt_generic_deinit success');
ok(mcrypt_module_close($td)>=0, 'mcrypt_module_close success');

# mdecrypt_generic
$td = mcrypt_module_open('twofish','','cbc','');
mcrypt_generic_init($td, $key, $iv);
$decrypted = mdecrypt_generic($td, $ciphertext);
is($decrypted, $plaintext, "mdecrypt_generic");

ok(mcrypt_generic_end($td)>=0, 'mcrypt_generic_end success');

$td = mcrypt_module_open('twofish','','cbc','');
mcrypt_generic_init($td, $key, $iv);
mcrypt_generic($td,$plaintext);

$state = mcrypt_enc_get_state($td);
ok(length($state), "mcrypt_enc_get_state success");
$ciphertext = mcrypt_generic($td,$plaintext);

# mcrypt_enc_set_state
ok(mcrypt_enc_set_state($td,$state)==0, "mcrypt_enc_set_state success");
# should get the same thing this time, given same state in machine
is($ciphertext, mcrypt_generic($td,$plaintext),
    "expected result after mcrypt_enc_set_state");

is(mcrypt_enc_self_test($td),0,"mcrypt_enc_self_test success");
mcrypt_generic_deinit($td);
mcrypt_module_close($td);

@known_combos = (
    {
        algo                => 'twofish',
        mode                => 'cbc',
        block_algo_mode     => 1,
        block_algo          => 1,
        block_mode          => 1,
        block_size          => 16,
        key_size            => 32,
        supported_key_sizes => [16,24,32],
        iv_size             => 16,
        mode_has_iv         => 1,
        algo_name           => 'Twofish',
        mode_name           => 'CBC',
    },
    {
        algo                => 'tripledes',
        mode                => 'cfb',
        block_algo_mode     => 1,
        block_algo          => 1,
        block_mode          => 0,
        block_size          => 8,
        key_size            => 24,
        supported_key_sizes => [24],
        iv_size             => 8,
        mode_has_iv         => 1,
        algo_name           => '3DES',
        mode_name           => 'CFB',
    },
);

foreach (@known_combos) {
    $name = $_->{name} || "$_->{algo} $_->{mode}";

    $td = mcrypt_module_open($_->{algo},'',$_->{mode},'');

    is(mcrypt_enc_is_block_algorithm_mode($td),$_->{block_algo_mode},
        "mcrypt_enc_is_block_algorithm_mode $name");

    is(mcrypt_enc_is_block_algorithm($td),$_->{block_algo},
        "mcrypt_enc_is_block_algorithm $name");

    is(mcrypt_enc_is_block_mode($td),$_->{block_mode},
        "mcrypt_enc_is_block_mode $name");

    is(mcrypt_enc_get_block_size($td),$_->{block_size},
        "mcrypt_enc_get_block_size $name");

    is(mcrypt_enc_get_key_size($td),$_->{key_size},
        "mcrypt_enc_get_key_size $name");

    is_deeply([mcrypt_enc_get_supported_key_sizes($td)],
        $_->{supported_key_sizes},
        "mcrypt_enc_get_supported_key_sizes $name");

    is(mcrypt_enc_get_iv_size($td),$_->{iv_size},
        "mcrypt_enc_get_iv_size $name");

    is(mcrypt_enc_mode_has_iv($td),$_->{mode_has_iv},
        "mcrypt_enc_mode_has_iv $name");

    is(mcrypt_enc_get_algorithms_name($td),$_->{algo_name},
        "mcrypt_enc_get_algorithms_name $name");

    is(mcrypt_enc_get_modes_name($td),$_->{mode_name},
        "mcrypt_enc_get_modes_name $name");

    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
}

ok(mcrypt_module_self_test("twofish")==0, "mcrypt_module_self_test success");
ok(mcrypt_module_self_test("")!=0, "mcrypt_module_self_test failure");

ok(mcrypt_module_is_block_algorithm_mode("cbc")==1,
    "mcrypt_module_is_block_algorithm_mode true");
ok(mcrypt_module_is_block_algorithm_mode("stream")==0,
    "mcrypt_module_is_block_algorithm_mode false");
ok(mcrypt_module_is_block_algorithm_mode("")<0,
    "mcrypt_module_is_block_algorithm_mode failure");

ok(mcrypt_module_is_block_algorithm("tripledes")==1,
    "mcrypt_module_is_block_agorithm true");
ok(mcrypt_module_is_block_algorithm("enigma")==0,
    "mcrypt_module_is_block_agorithm false");
ok(mcrypt_module_is_block_algorithm("")<0,
    "mcrypt_module_is_block_agorithm failure");

ok(mcrypt_module_is_block_mode("cbc")==1,
    "mcrypt_module_is_block_mode true");
ok(mcrypt_module_is_block_mode("cfb")==0,
    "mcrypt_module_is_block_mode false");
ok(mcrypt_module_is_block_mode("")<0,
    "mcrypt_module_is_block_mode failure");

is(mcrypt_module_get_algo_block_size("tripledes"), 8,
    "mcrypt_module_get_algo_block_size success");
is(mcrypt_module_get_algo_block_size(""), -1,
    "mcrypt_module_get_algo_block_size failure");

is(mcrypt_module_get_algo_key_size("tripledes"), 24,
    "mcrypt_module_get_algo_key_size success");
is(mcrypt_module_get_algo_key_size(""), -1,
    "mcrypt_module_get_algo_key_size failure");

is_deeply([mcrypt_module_get_algo_supported_key_sizes("twofish")],
          [16,24,32],
          "mcrypt_module_get_algo_supported_key_sizes success");
is_deeply([mcrypt_module_get_algo_supported_key_sizes("")],
          [],
          "mcrypt_module_get_algo_supported_key_sizes failure");

1;
