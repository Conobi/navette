"""SipHash: reference vectors (2-4 from the paper, 1-3 cross-checked against Rust's DefaultHasher) and properties."""

from navette.util.siphash import SipKey, siphash, siphash13
from tests._test_util import assert_true
from tests.protect._prop import Rng


def _ref_key() -> SipKey:
    """The paper's key: bytes 00..0f."""
    return SipKey(k0=UInt64(0x0706050403020100), k1=UInt64(0x0F0E0D0C0B0A0908))


def _seq(n: Int) -> List[Byte]:
    var out = List[Byte](capacity=n)
    for i in range(n):
        out.append(Byte(i))
    return out^


def test_siphash24_reference_vectors() raises:
    var k = _ref_key()
    var lens = [0, 1, 2, 3, 7, 8, 15, 16, 17, 63]
    var want: List[UInt64] = [
        0x726FDB47DD0E0E31, 0x74F839C593DC67FD, 0x0D6C8009D9A94F5A,
        0x85676696D7FB7E2D, 0xAB0200F58B01D137, 0x93F5F5799A932462,
        0xA129CA6149BE45E5, 0x3F2ACC7F57C29BDB, 0x699AE9F52CBE4794,
        0x958A324CEB064572,
    ]
    for i in range(len(lens)):
        var m = _seq(lens[i])
        assert_true(siphash[2, 4](k, Span(m)) == want[i], "siphash24 len " + String(lens[i]))
    print("PASS: test_siphash24_reference_vectors")


def test_siphash13_reference_vectors() raises:
    var k = _ref_key()
    var lens = [0, 1, 7, 8, 15, 16, 17, 20]
    var want: List[UInt64] = [
        0xABAC0158050FC4DC, 0xC9F49BF37D57CA93, 0xD3927D989BB11140,
        0x369095118D299A8E, 0xD320D86D2A519956, 0xCC4FDD1A7D908B66,
        0x9CF2689063DBD80C, 0xC0DC2F46A6CCE040,
    ]
    for i in range(len(lens)):
        var m = _seq(lens[i])
        assert_true(siphash13(k, Span(m)) == want[i], "siphash13 len " + String(lens[i]))
    # Rust DefaultHasher::new() is SipHash-1-3 with a zero key.
    var z = SipKey(k0=UInt64(0), k1=UInt64(0))
    var m20 = _seq(20)
    assert_true(siphash13(z, Span(m20)) == UInt64(0x639E355AE68C0100), "zero key len 20")
    print("PASS: test_siphash13_reference_vectors")


def test_siphash13_every_length_to_64() raises:
    """Key 00..0f, message 00..n-1, n = 0..64: every tail length and block count up to eight blocks.

    Expected values come from an independent Python SipHash-c-d that
    reproduces the paper's 2-4 vectors.
    """
    var k = _ref_key()
    var want: List[UInt64] = [
        0xABAC0158050FC4DC, 0xC9F49BF37D57CA93, 0x82CB9B024DC7D44D,
        0x8BF80AB8E7DDF7FB, 0xCF75576088D38328, 0xDEF9D52F49533B67,
        0xC50D2B50C59F22A7, 0xD3927D989BB11140, 0x369095118D299A8E,
        0x25A48EB36C063DE4, 0x79DE85EE92FF097F, 0x70C118C1F94DC352,
        0x78A384B157B4D9A2, 0x306F760C1229FFA7, 0x605AA111C0F95D34,
        0xD320D86D2A519956, 0xCC4FDD1A7D908B66, 0x9CF2689063DBD80C,
        0x8FFC389CB473E63E, 0xF21F9DE58D297D1C, 0xC0DC2F46A6CCE040,
        0xB992ABFE2B45F844, 0x7FFE7B9BA320872E, 0x525A0E7FDAE6C123,
        0xF464AEB267349C8C, 0x45CD5928705B0979, 0x3A3E35E3CA9913A5,
        0xA91DC74E4ADE3B35, 0xFB0BED02EF6CD00D, 0x88D93CB44AB1E1F4,
        0x540F11D643C5E663, 0x2370DD1F8C21D1BC, 0x81157B6C16A7B60D,
        0x4D54B9E57A8FF9BF, 0x759F12781F2A753E, 0xCEA1A3BEBF186B91,
        0x2CF508D3ADA26206, 0xB6101C2DA3C33057, 0xB3F47496AE3A36A1,
        0x626B57547B108392, 0xC1D2363299E41531, 0x667CC1923F1AD944,
        0x65704FFEC8138825, 0x24F280D1C28949A6, 0xC2CA1CEDFAF8876B,
        0xC2164BFC9F042196, 0xA16E9C9368B1D623, 0x49FB169C8B5114FD,
        0x9F3143F8DF074C46, 0xC6FDAF2412CC86B3, 0x7EAF49D10A52098F,
        0x1CF313559D292F9A, 0xC44A30DDA2F41F12, 0x36FAE98943A71ED0,
        0x318FB34C73F0BCE6, 0xA27ABF3670A7E980, 0xB4BCC0DB243C6D75,
        0x23F8D852FDB71513, 0x8F035F4DA67D8A08, 0xD89CD0E5B7E8F148,
        0xF6F4E6BCF7A644EE, 0xAEC59AD80F1837F2, 0xC3B2F6154B6694E0,
        0x9D199062B7BBB3A8, 0xF17997EC4B4A6065,
    ]
    for n in range(65):
        var m = _seq(n)
        assert_true(siphash13(k, Span(m)) == want[n], "siphash13 len " + String(n))
    print("PASS: test_siphash13_every_length_to_64")


def test_siphash_key_sensitivity_property() raises:
    """Flipping any single key bit changes the hash of a random message (5,000 cases)."""
    var rng = Rng(0x5195)
    for _ in range(5000):
        var m = rng.bytes(rng.below(33))
        var k = SipKey(k0=rng.next(), k1=rng.next())
        var bit = rng.below(128)
        var k2 = SipKey(k0=k.k0, k1=k.k1)
        if bit < 64:
            k2.k0 ^= UInt64(1) << UInt64(bit)
        else:
            k2.k1 ^= UInt64(1) << UInt64(bit - 64)
        assert_true(siphash13(k, Span(m)) != siphash13(k2, Span(m)), "key bit flip changes hash")
    print("PASS: test_siphash_key_sensitivity_property")


def test_random_keys_differ() raises:
    var a = SipKey.random()
    var b = SipKey.random()
    assert_true(a.k0 != b.k0 or a.k1 != b.k1, "two getrandom keys differ")
    print("PASS: test_random_keys_differ")


def main() raises:
    test_siphash24_reference_vectors()
    test_siphash13_reference_vectors()
    test_siphash13_every_length_to_64()
    test_siphash_key_sensitivity_property()
    test_random_keys_differ()
