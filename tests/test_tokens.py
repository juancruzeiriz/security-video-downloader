import time

from svd import tokens

SECRET = "clave-de-prueba-super-larga-1234567890"
ACL = "/demo0001-0000-0000-0000-000000000001/adaptive_video/*"
PATH_OK = "/demo0001-0000-0000-0000-000000000001/adaptive_video/-/variant/480p/4/"


def test_sign_and_verify_ok():
    token = tokens.sign(SECRET, ACL, ttl=3600)
    result = tokens.verify(SECRET, token, PATH_OK)
    assert result.ok
    assert result.reason == "ok"


def test_token_roundtrip_fields():
    token = tokens.sign(SECRET, ACL, expires_at=1791240149)
    parsed = tokens.parse(token)
    assert parsed.exp == 1791240149
    assert parsed.acl == ACL
    assert len(parsed.hmac) == 64  # sha256 hex


def test_expired_token():
    token = tokens.sign(SECRET, ACL, expires_at=int(time.time()) - 10)
    result = tokens.verify(SECRET, token, PATH_OK)
    assert not result
    assert result.reason == "expired"


def test_acl_mismatch():
    token = tokens.sign(SECRET, ACL, ttl=3600)
    result = tokens.verify(SECRET, token, "/otro-id/adaptive_video/4/")
    assert not result
    assert result.reason == "acl_mismatch"


def test_bad_signature_wrong_secret():
    token = tokens.sign(SECRET, ACL, ttl=3600)
    result = tokens.verify("otra-clave", token, PATH_OK)
    assert not result
    assert result.reason == "bad_signature"


def test_tampered_hmac():
    token = tokens.sign(SECRET, ACL, ttl=3600)
    tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
    result = tokens.verify(SECRET, tampered, PATH_OK)
    assert not result
    assert result.reason == "bad_signature"


def test_malformed_token():
    result = tokens.verify(SECRET, "esto-no-es-un-token", PATH_OK)
    assert not result
    assert result.reason.startswith("malformed")


def test_acl_wildcard_matches_master_and_segments():
    assert tokens.acl_matches(ACL, "/demo0001-0000-0000-0000-000000000001/adaptive_video/master.m3u8")
    assert tokens.acl_matches(ACL, "/demo0001-0000-0000-0000-000000000001/adaptive_video/variant_0/seg_000.ts")
    assert not tokens.acl_matches(ACL, "/demo0001-0000-0000-0000-000000000001/otro/master.m3u8")
