package compression

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func goldenInputs() (httpish, jsonish, repetitive, mixed []byte) {
	httpish = []byte(strings.Repeat("GET /api/v1/users?page=2 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\nContent-Type: application/json\r\n", 12))
	jsonish = []byte(strings.Repeat(`{"id":12345,"name":"example-user","status":"active","role":"member","email":"user42@example.com"}`, 20))
	repetitive = bytes.Repeat([]byte("abcabcabcabcabcabcabcabc"), 16)
	mixed = append(append([]byte{}, httpish...), jsonish...)
	return httpish, jsonish, repetitive, mixed
}

// TestCompressPayloadGoldenByteIdentity proves that with the zero
// (never-configured / restored) settings, CompressPayload output is
// byte-identical to the pre-pack code at 2424e95. The expected frames
// were captured from the unmodified code before the dictionary work
// (see /tmp/golden-2424e95.json, captured 2026-11-03) and are embedded
// here so the guarantee survives in the repo.
func TestCompressPayloadGoldenByteIdentity(t *testing.T) {
	Configure(ZSTDOptions{})
	defer Configure(ZSTDOptions{})

	httpish, jsonish, repetitive, mixed := goldenInputs()
	cases := []struct {
		name string
		data []byte
		typ  uint8
		hex  string
	}{
		{"repetitive-zlib", repetitive, TypeZLIB, "ecd0310d000000c230ad807f0fc8d8b3a40a9a4ee0c0030000ffff"},
		{"repetitive-zstd", repetitive, TypeZSTD, "28b52ffd440080005d000018616263015403022c7a0686a541c7"},
		{"repetitive-lz4", repetitive, TypeLZ4, "800100003f6162630300ff5b006b01c0616263616263616263616263"},
		{"httpish-zstd", httpish, TypeZSTD, "28b52ffd6470041d03000286151a704b1b40a02cbddc0b89920060c71fb3dbdb18650e00a03c2f35fb47029a6d332e98c3b82990f16a554bf9f590fe2a453067618556f9a28e45eb7a48374ecc4928212233b9806013fa415b6c63606ae0bae2a5e1100200f9dce10770d0ca0c10f47e30"},
		{"httpish-lz4", httpish, TypeLZ4, "70050000ff51474554202f6170692f76312f75736572733f706167653d3220485454502f312e310d0a486f73743a206170692e6578616d706c652e636f6d0d0a4163636570743a206170706c69636174696f6e2f6a736f6e0d0a436f6e74656e742d547970652000010f7400ffffffffdd001c05c06174696f6e2f6a736f6e0d0a"},
		{"jsonish-zstd", jsonish, TypeZSTD, "28b52ffd649406bd0200a2851218808909634122f7f0b7ebc0f73bfc26eed2b78766a13fef448d3341028572a0a6f57d0c66b7510dd9fcee49d076154621f89d964295b651d302f4241217fd6e2262231c8322b80f66460210063093bfa8c1350320e557f7"},
		{"mixed-zstd", mixed, TypeZSTD, "28b52ffd64040c4d0500328b2420500bab005bbc6f7323b2c61c8cb67639767236ceb4e9fbd1ed0ad5818050818611779025022511959baf332d9d1e3daa8253f77565603cba2e5ab3fc3a379dcd478fca0df27575f98e0212004ab2bed00ea1fbb020fdb41f34308e07b9413dd83a596376f3ac5e65acc0381c64499975e9a0a96d9ed50c15c691a444252c8be22802ca903bc051b951c942b54d7596038405003093f14b0ec1415aa5cbf9dcf80770d0ca0c7b978d60"},
		{"mixed-zlib", mixed, TypeZLIB, "ec94cf4a04310cc6ef03f30e25e7d92933ae9782a888b8470f7d81588374e99fb0cd0e8af8ee52f4e0cd07d89c9310f8f87ebfa7476f2c72b4db62cf8d4eed96f18d6e5673f0fed92ef3320e87dac419e438d33b664e34879ac7e13e0462710699530c28b1167b6cb58cc3432d424576fe83c919644e31e09fb9fed46cb5434765e5029df009f115dcb25eedaf272898091cd08f5677ddbf3041139473030718246e04139c6aea7b99f20bf50dca181338e807fbf5eef7be23055ffa4023ea1dd116296830a92a9403e5e01f0ebe030000ffff"},
	}
	for _, c := range cases {
		want, err := hex.DecodeString(c.hex)
		if err != nil {
			t.Fatal(err)
		}
		got, used := CompressPayload(c.data, c.typ, DefaultMinSize)
		if used != c.typ {
			t.Fatalf("%s: used=%d want=%d", c.name, used, c.typ)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: output differs from 2424e95 golden: got %d bytes, want %d bytes", c.name, len(got), len(want))
		}
		// The direct zstd path must agree with CompressPayload for
		// zstd cases (it did pre-change, and both share the pool).
		if c.typ == TypeZSTD {
			direct, err := compressZSTD(c.data)
			if err != nil || !bytes.Equal(direct, want) {
				t.Fatalf("%s: direct compressZSTD differs from golden", c.name)
			}
		}
	}
}

func TestEmbeddedDictionaries(t *testing.T) {
	if len(uploadDictionary) == 0 || len(downloadDictionary) == 0 {
		t.Fatal("embedded dictionaries must not be empty")
	}
	if len(uploadDictionary) > maxDictionarySize {
		t.Fatalf("upload dictionary %d bytes exceeds cap %d", len(uploadDictionary), maxDictionarySize)
	}
	if len(downloadDictionary) > maxDictionarySize {
		t.Fatalf("download dictionary %d bytes exceeds cap %d", len(downloadDictionary), maxDictionarySize)
	}
	if bytes.Equal(uploadDictionary, downloadDictionary) {
		t.Fatal("upload and download dictionaries must differ")
	}
	up, err := zstd.InspectDictionary(uploadDictionary)
	if err != nil {
		t.Fatalf("upload dictionary: %v", err)
	}
	down, err := zstd.InspectDictionary(downloadDictionary)
	if err != nil {
		t.Fatalf("download dictionary: %v", err)
	}
	if up.ID() != UploadDictionaryID || up.ID() == 0 {
		t.Fatalf("upload dictionary ID=%d want %d", up.ID(), UploadDictionaryID)
	}
	if down.ID() != DownloadDictionaryID || down.ID() == 0 {
		t.Fatalf("download dictionary ID=%d want %d", down.ID(), DownloadDictionaryID)
	}
	if up.ID() == down.ID() {
		t.Fatal("dictionary IDs must be distinct so the decoder can select by ID")
	}
	if up.ContentSize() == 0 || down.ContentSize() == 0 {
		t.Fatal("dictionaries must carry content, not only tables")
	}
}

func TestConfigureClampsLevel(t *testing.T) {
	defer Configure(ZSTDOptions{})
	Configure(ZSTDOptions{Level: -5})
	if got := currentZSTDOptions().Level; got != 0 {
		t.Fatalf("level -5 clamped to %d, want 0", got)
	}
	Configure(ZSTDOptions{Level: 99})
	if got := currentZSTDOptions().Level; got != 22 {
		t.Fatalf("level 99 clamped to %d, want 22", got)
	}
	Configure(ZSTDOptions{DictEnabled: true, Level: 9, LongEnabled: true})
	got := currentZSTDOptions()
	if !got.DictEnabled || got.Level != 9 || !got.LongEnabled {
		t.Fatalf("options not stored: %+v", got)
	}
}

func TestDictRoundTrips(t *testing.T) {
	httpish, jsonish, _, mixed := goldenInputs()
	small := []byte(strings.Repeat("GET /api/v1/items?id=42 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n", 3))
	inputs := [][]byte{httpish, jsonish, mixed, small}

	configs := []ZSTDOptions{
		{DictEnabled: true, Level: 0},
		{DictEnabled: true, Level: 3},
		{DictEnabled: true, Level: 9, LongEnabled: true},
		{DictEnabled: true, Level: 19, LongEnabled: true},
		{DictEnabled: true, Level: 19},
	}
	for _, cfg := range configs {
		Configure(cfg)
		for _, in := range inputs {
			// Direction-blind path (both dicts tried).
			comp, used := CompressPayload(in, TypeZSTD, DefaultMinSize)
			if used != TypeZSTD {
				t.Fatalf("cfg %+v: CompressPayload did not use ZSTD", cfg)
			}
			back, ok := TryDecompressPayload(comp, used)
			if !ok || !bytes.Equal(back, in) {
				t.Fatalf("cfg %+v: auto round-trip failed", cfg)
			}
			// Direction-specific paths, alternating through the
			// pooled decoder to prove Reset reuse across dict IDs.
			for _, dict := range []Dictionary{DictUpload, DictDownload} {
				comp, used := CompressPayloadForDirection(in, TypeZSTD, DefaultMinSize, dict)
				if used != TypeZSTD {
					t.Fatalf("cfg %+v dict %d: did not use ZSTD", cfg, dict)
				}
				back, ok := TryDecompressPayload(comp, used)
				if !ok || !bytes.Equal(back, in) {
					t.Fatalf("cfg %+v dict %d: round-trip failed", cfg, dict)
				}
			}
		}
	}
	Configure(ZSTDOptions{})
}

func TestDictFramesFailClosedWithoutDictConfig(t *testing.T) {
	defer Configure(ZSTDOptions{})
	httpish, _, _, _ := goldenInputs()

	// Encode with dictionaries, then drop back to the legacy config:
	// the peer without dictionary support must reject the frame
	// (TryDecompressPayload false), never emit wrong bytes. This is
	// also the behavior on a dictionary-version mismatch, where the
	// frame's dictionary ID is unknown to the decoder.
	Configure(ZSTDOptions{DictEnabled: true, Level: 9})
	comp, used := CompressPayload(httpish, TypeZSTD, DefaultMinSize)
	if used != TypeZSTD {
		t.Fatal("dict encode did not use ZSTD")
	}
	Configure(ZSTDOptions{})
	if back, ok := TryDecompressPayload(comp, used); ok {
		t.Fatalf("dict frame decoded without dict config; got %d bytes (must fail closed)", len(back))
	}

	// And the reverse direction: legacy (dictionary-free) frames
	// must still decode once dictionaries are enabled.
	legacy, used := CompressPayload(httpish, TypeZSTD, DefaultMinSize)
	if used != TypeZSTD {
		t.Fatal("legacy encode did not use ZSTD")
	}
	Configure(ZSTDOptions{DictEnabled: true, Level: 9})
	back, ok := TryDecompressPayload(legacy, used)
	if !ok || !bytes.Equal(back, httpish) {
		t.Fatal("legacy frame must decode under dict config")
	}
}

func TestDictSmallFrameBeatsNoDict(t *testing.T) {
	defer Configure(ZSTDOptions{})
	// A short request-shaped frame just above the min-size gate: the
	// case dictionaries exist for. The dictionary frame must be no
	// larger than the dictionary-free frame.
	frame := []byte("GET /api/v1/users?page=3&limit=25 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\nAuthorization: Bearer synthetic-aaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n")

	Configure(ZSTDOptions{})
	plain, used := CompressPayload(frame, TypeZSTD, DefaultMinSize)
	if used != TypeZSTD {
		t.Skip("frame went raw without dict; cannot compare")
	}
	Configure(ZSTDOptions{DictEnabled: true, Level: 9})
	withDict, used := CompressPayload(frame, TypeZSTD, DefaultMinSize)
	if used != TypeZSTD {
		t.Fatal("dict encode went raw")
	}
	if len(withDict) > len(plain) {
		t.Fatalf("dict frame %d bytes larger than plain frame %d bytes", len(withDict), len(plain))
	}
	t.Logf("small frame: plain=%d dict=%d raw=%d", len(plain), len(withDict), len(frame))
}

func TestDictGuardsPreserved(t *testing.T) {
	defer Configure(ZSTDOptions{})
	Configure(ZSTDOptions{DictEnabled: true, Level: 19, LongEnabled: true})

	// High-entropy input still goes raw (entropy gate), even with
	// dictionaries enabled.
	random := make([]byte, 4096)
	seed := uint32(1)
	for i := range random {
		seed = seed*1664525 + 1013904223
		random[i] = byte(seed >> 24)
	}
	out, used := CompressPayload(random, TypeZSTD, DefaultMinSize)
	if used != TypeOff || !bytes.Equal(out, random) {
		t.Fatal("high-entropy payload must bypass compression even with dict enabled")
	}

	// Size check: a compressed result is never returned when it is
	// not smaller than the input.
	httpish, _, _, _ := goldenInputs()
	comp, used := CompressPayload(httpish, TypeZSTD, DefaultMinSize)
	if used == TypeZSTD && len(comp) >= len(httpish) {
		t.Fatal("size check violated: compressed >= input yet marked compressed")
	}
}
