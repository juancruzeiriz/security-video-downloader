from svd import hls

MASTER = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=1400000,RESOLUTION=854x480,CODECS="avc1.64001f,mp4a.40.2"
variant_0/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=600000,RESOLUTION=640x360,CODECS="avc1.64001e,mp4a.40.2"
variant_1/index.m3u8
"""

MEDIA = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:2.000,
seg_000.ts
#EXTINF:2.000,
seg_001.ts
#EXTINF:1.500,
seg_002.ts
#EXT-X-ENDLIST
"""

MEDIA_AES = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-KEY:METHOD=AES-128,URI="key.bin",IV=0x00000000000000000000000000000000
#EXTINF:2.000,
seg_000.ts
#EXT-X-ENDLIST
"""


def test_is_master():
    assert hls.is_master(MASTER)
    assert not hls.is_master(MEDIA)


def test_parse_master():
    variants = hls.parse_master(MASTER)
    assert len(variants) == 2
    assert variants[0].uri == "variant_0/index.m3u8"
    assert variants[0].bandwidth == 1400000
    assert variants[0].resolution == "854x480"
    assert variants[0].height == 480
    assert variants[1].height == 360


def test_parse_media():
    pl = hls.parse_media(MEDIA)
    assert pl.target_duration == 2
    assert [s.uri for s in pl.segments] == ["seg_000.ts", "seg_001.ts", "seg_002.ts"]
    assert pl.segments[0].duration == 2.0
    assert pl.segments[2].duration == 1.5
    assert not pl.is_encrypted


def test_parse_media_encrypted():
    pl = hls.parse_media(MEDIA_AES)
    assert pl.is_encrypted
    assert pl.segments[0].key is not None
    assert pl.segments[0].key.method == "AES-128"
    assert pl.segments[0].key.uri == "key.bin"


def test_resolve():
    assert hls.resolve("http://localhost:8000/a/b/master.m3u8", "variant_0/index.m3u8") == (
        "http://localhost:8000/a/b/variant_0/index.m3u8"
    )
