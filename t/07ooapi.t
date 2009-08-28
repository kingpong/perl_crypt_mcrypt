#!/usr/bin/perl
use blib;
use strict;
use Test::More tests => 105;
use Crypt::Mcrypt;

#
# Test the Crypt::Mcrypt object-oriented API in the order in which it is
# described in the POD.
#

my $key = '0123456789012345';  # 16-byte (128-bit) key
my $iv  = '0123456789012345';  # 16-byte (128-bit) IV

my $mc = Crypt::Mcrypt->new;
ok($mc, 'new no args success');
isa_ok($mc, 'Crypt::Mcrypt', 'new no args isa Crypt::Mcrypt');

$mc = Crypt::Mcrypt->new({
    algorithm => 'tripledes',
    mode      => 'cbc',
    key       => $key,
    iv        => $iv,
    algorithm_dir  => "/algo",   # won't be using, just checking passthrough
    mode_dir  => "/mode",   # "
});
ok($mc, 'new args success');
isa_ok($mc, 'Crypt::Mcrypt', 'new args isa Crypt::Mcrypt');
is($mc->algorithm, 'tripledes', 'new args algorithm init ok');
is($mc->algo, 'tripledes', 'new args algo init alias ok');
is($mc->mode, 'cbc', 'new args mode init ok');
is($mc->key, $key, 'new args key init ok');
is($mc->iv, $iv, 'new args iv init ok');
is($mc->algorithm_dir, '/algo', 'new args algorithm_dir init alias ok');
is($mc->algo_dir, '/algo', 'new args algo_dir init ok');
is($mc->mode_dir, '/mode', 'new args mode_dir init ok');

$mc = Crypt::Mcrypt->new({
    algo     => 'tripledes',
    mode     => 'cbc',
    key      => $key,
    iv       => $iv,
    algo_dir => "/algo",   # won't be using, just checking passthrough
    mode_dir => "/mode",   # "
});
ok($mc, 'new args alias success');
isa_ok($mc, 'Crypt::Mcrypt', 'new args alias isa Crypt::Mcrypt');
is($mc->algo, 'tripledes', 'new args alias algo ok');
is($mc->algorithm, 'tripledes', 'new args alias algorithm ok');
is($mc->algo_dir, '/algo', 'new args alias algo_dir ok');
is($mc->algorithm_dir, '/algo', 'new args alias algorithm_dir ok');

$mc = Crypt::Mcrypt->new(algorithm => 'tripledes');
ok($mc, 'new flat args success');
isa_ok($mc, 'Crypt::Mcrypt', 'new flat args isa Crypt::Mcrypt');
is($mc->algo, 'tripledes', 'new flat args algo init ok');

$mc = Crypt::Mcrypt->new;

ok( scalar(grep { $_ eq 'tripledes' } Crypt::Mcrypt->algorithms),
    "class algorithms ok");
ok( scalar(grep { $_ eq 'tripledes' } Crypt::Mcrypt->algos),
    "class algos ok");
ok( scalar(grep { $_ eq 'tripledes' } $mc->algos),
    "instance algos ok");

ok( scalar(grep { $_ eq 'cbc' } Crypt::Mcrypt->modes),
    "class modes ok");
ok( scalar(grep { $_ eq 'cbc' } $mc->modes),
    "instance modes ok");

ok( Crypt::Mcrypt->module_self_test("tripledes"),
    "class module_self_test ok");
ok( !Crypt::Mcrypt->module_self_test(""),
    "class module_self_test not ok");
ok( $mc->module_self_test("tripledes"),
    "instance module_self_test ok");
ok( !$mc->module_self_test(""),
    "instance module_self_test not ok");

my %algo_info = (
    'tripledes' => {
        is_block_algorithm => 1,
        max_key_size => 24,
        block_size => 8,
    },
    'arcfour' => {
        is_block_algorithm => 0,
        max_key_size => 256,
        block_size => 1,
    },
);

foreach ('Crypt::Mcrypt', $mc) {
    while (my ($algo,$should) = each %algo_info) {
        my $got = $_->algorithm_info($algo);
        is($got->{is_block_algorithm}, $should->{is_block_algorithm},
            "$_ algorithm_info is_block_algorithm $algo");
        is($got->{max_key_size}, $should->{max_key_size},
            "$_ algorithm_info max_key_size $algo");
        is($got->{block_size}, $should->{block_size},
            "$_ algorithm_info block_size $algo");
        ok($got->{version}, "$_ algorithm_info version $algo");
    }
}

my %mode_info = (
    'cbc' => {
        is_block_algorithm_mode => 1,
        is_block_mode => 1,
    },
    'cfb' => {
        is_block_algorithm_mode => 1,
        is_block_mode => 0,
    },
    'stream' => {
        is_block_algorithm_mode => 0,
        is_block_mode => 0,
    },
);

foreach ('Crypt::Mcrypt', $mc) {
    while (my ($mode,$should) = each %mode_info) {
        my $got = $_->mode_info($mode);
        is($got->{is_block_mode}, $should->{is_block_mode},
            "$_ mode_info is_block_mode $mode");
        is($got->{max_key_size}, $should->{max_key_size},
            "$_ mode_info max_key_size $mode");
        is($got->{block_size}, $should->{block_size},
            "$_ mode_info block_size $mode");
        ok($got->{version}, "$_ mode_info version $mode");
    }
}

is(Crypt::Mcrypt->check_version("2.0.0"), Crypt::Mcrypt::API::LIBMCRYPT_VERSION(),
    "class check_version ok");
is($mc->check_version("2.0.0"), Crypt::Mcrypt::API::LIBMCRYPT_VERSION(),
    "instance check_version ok");
ok(!Crypt::Mcrypt->check_version("100.0.0"), "class check_version not ok");
ok(!$mc->check_version("100.0.0"), "instance check_version not ok");

# instance methods from here on
$mc = Crypt::Mcrypt->new;
is($mc->algorithm, undef, "algorithm init undef");
$mc->algorithm("tripledes");
is($mc->algorithm, "tripledes", "algorithm set ok");
is($mc->algo, "tripledes", "algo alias ok after algorithm set");
$mc->algo("twofish");
is($mc->algorithm, "twofish", "algo set ok");
is($mc->algo, "twofish", "algo alias ok after algo set");

is($mc->mode, undef, "mode init undef");
$mc->mode("cbc");
is($mc->mode, "cbc", "mode set ok");

is($mc->algorithm_dir, undef, "algorithm_dir init undef");
$mc->algorithm_dir("/algo");
is($mc->algorithm_dir, "/algo", "algorithm_dir set ok");
is($mc->algo_dir, "/algo", "algo_dir alias ok after algorithm_dir set");
$mc->algo_dir("twofish");
is($mc->algorithm_dir, "twofish", "algo_dir set ok");
is($mc->algo_dir, "twofish", "algo_dir alias ok after algo_dir set");
$mc->algo_dir(undef);
is($mc->algo_dir, undef, "allow algo_dir reset to undef");

is($mc->mode_dir, undef, "mode_dir init undef");
$mc->mode_dir("/mode");
is($mc->mode_dir, "/mode", "mode_dir set ok");
$mc->mode_dir(undef);
is($mc->mode_dir, undef, "allow mode_dir reset to undef");

is($mc->key, undef, "key init undef");
$mc->key($key);
is($mc->key, $key, "key set ok");
$mc->key(undef);
is($mc->key, undef, "allow key reset ok");

is($mc->iv, undef, "iv init undef");
$mc->iv($iv);
is($mc->iv, $iv, "iv set ok");
$mc->iv(undef);
is($mc->iv, undef, "allow iv reset ok");

is($mc->errcode, undef, "errcode init ok");
$mc->algo("my des");
$mc->mode("cbc");
$mc->key("a");
$mc->encrypt("foo");    # should set error, no such algo
ok($mc->errcode, "errcode set as expected");

$mc->algo(undef);
eval { $mc->supported_key_sizes };
ok($@, "supported_key_sizes no algo dies");

$mc->algo('twofish');
is_deeply([$mc->supported_key_sizes], [128/8,192/8,256/8],
    'supported_key_sizes ok');

$mc->algo(undef);
eval { $mc->self_test };
ok($@, "self_test no algo dies");

$mc->algo('twofish');
ok($mc->self_test, "self_test ok");

$mc->algo('twofish');
$mc->mode('cbc');
$mc->key($key);
$mc->iv($iv);
my $info = $mc->info;
is_deeply($mc->info, {
    block_size              => 128/8,
    iv_size                 => 16,
    key_size                => 256/8,
    max_key_size            => 256/8,
    is_block_algorithm      => 1,
    is_block_mode           => 1,
    is_block_algorithm_mode => 1,
    mode_has_iv             => 1,
    algorithm_name          => 'Twofish',
    algorithms_name         => 'Twofish', # compatibility
    mode_name               => 'CBC',
    modes_name              => 'CBC',     # compatibility
}, "mc info ok");

$mc->padding('pkcs7');
$mc->encrypt("a");
my $state = $mc->get_state;
my $out1 = $mc->encrypt("b");
ok(length($state), "get_state ok");
$mc->set_state($state);
my $out2 = $mc->encrypt("b");
is($out1, $out2, "set_state ok");


