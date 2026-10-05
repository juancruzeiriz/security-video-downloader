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


# -- Etapa 2: binding de sesion/IP y rotacion de clave ----------------------

def test_session_binding_requires_matching_session():
    token = tokens.sign(SECRET, ACL, ttl=3600, session="S1")
    assert tokens.verify(SECRET, token, PATH_OK, session="S1").ok
    bad = tokens.verify(SECRET, token, PATH_OK, session="S2")
    assert not bad and bad.reason == "session_mismatch"
    # sin pasar la sesion del pedido tampoco valida
    assert tokens.verify(SECRET, token, PATH_OK).reason == "session_mismatch"


def test_ip_binding_requires_matching_ip():
    token = tokens.sign(SECRET, ACL, ttl=3600, ip="203.0.113.7")
    assert tokens.verify(SECRET, token, PATH_OK, client_ip="203.0.113.7").ok
    bad = tokens.verify(SECRET, token, PATH_OK, client_ip="198.51.100.9")
    assert not bad and bad.reason == "ip_mismatch"


def test_binding_fields_are_signed():
    # cambiar la sesion del token sin re-firmar rompe la firma
    token = tokens.sign(SECRET, ACL, ttl=3600, session="S1")
    tampered = token.replace("session=S1", "session=S2")
    res = tokens.verify(SECRET, tampered, PATH_OK, session="S2")
    assert not res and res.reason == "bad_signature"


def test_token_without_binding_stays_backward_compatible():
    # un token clasico (solo exp~acl~hmac) no impone binding
    token = tokens.sign(SECRET, ACL, ttl=3600)
    assert tokens.verify(SECRET, token, PATH_OK).ok
    parsed = tokens.parse(token)
    assert parsed.session is None and parsed.ip is None


def test_key_rotation_list_accepts_either_key():
    new_key, old_key = "clave-nueva-xxxxxxxxxxxxxxxxxxxx", "clave-vieja-yyyyyyyyyyyyyyyyyyyy"
    token_old = tokens.sign(old_key, ACL, ttl=3600)
    # durante la rotacion se pasan ambas; vale la vieja
    assert tokens.verify([new_key, old_key], token_old, PATH_OK).ok
    # una clave ajena no valida
    assert not tokens.verify([new_key, "clave-ajena-zzzzzzzzzzzzzzzzzz"], token_old, PATH_OK)
