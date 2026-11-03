package compression

import (
	_ "embed"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Shared zstd dictionaries.
//
// Both dictionaries are trained offline by dicts/gen from SYNTHETIC,
// general-purpose samples only (HTTP request/response boilerplate, JSON
// API bodies, HTML templates; fixed seed, reserved *.example.com hosts).
// They are embedded so both ends of a tunnel always ship identical
// bytes; there is no runtime dictionary exchange and no negotiation
// beyond the existing compression-type nibble.
//
//go:embed dicts/upload-v1.dict
var uploadDictionary []byte

//go:embed dicts/download-v1.dict
var downloadDictionary []byte

const (
	// DictionaryVersion identifies the embedded dictionary pair. Bump
	// it (and the file names, and the IDs below) whenever the
	// dictionaries are retrained: dictionary IDs are written into
	// every dictionary frame, and decoders select the dictionary by
	// ID, so reusing an ID with different content would let a peer
	// decode old frames against the wrong dictionary.
	DictionaryVersion = "v1"

	// UploadDictionaryID / DownloadDictionaryID are the dictionary IDs
	// stored in the trained dictionaries (see dicts/gen). They must be
	// distinct and non-zero: the decoder keeps both dictionaries
	// keyed by ID, and a zero ID is rejected by the zstd format.
	UploadDictionaryID   uint32 = 1
	DownloadDictionaryID uint32 = 2

	// maxDictionarySize is the enforced cap for each embedded
	// dictionary. The dicts/gen generator refuses to emit a larger
	// dictionary, and TestEmbeddedDictionaries enforces the same cap
	// on the shipped files.
	maxDictionarySize = 64 * 1024

	// longWindowSize is the encoder window used when long-distance
	// matching is enabled (ZSTD_LONG_ENABLED). klauspost/compress
	// v1.18.5 exposes no separate long-distance-matching option; the
	// window size is the only equivalent control. 16 MiB is the
	// smallest power of two above the 10 MiB decompression cap, so a
	// "long" encoder can reference any offset inside any legal
	// frame. The default windows (4 MiB at SpeedFastest, 8 MiB at
	// higher levels) already cover most tunnel frames, so the long
	// window is expected to change little except at SpeedFastest and
	// on near-cap frames; it costs encoder memory, which the
	// benchmarks measure.
	longWindowSize = 16 << 20
)

// Dictionary selects which embedded dictionary an encoder uses.
type Dictionary int

const (
	// DictUpload is the request-shaped dictionary (HTTP requests,
	// JSON request bodies).
	DictUpload Dictionary = iota
	// DictDownload is the response-shaped dictionary (HTTP responses,
	// JSON responses, HTML pages).
	DictDownload
)

// ZSTDOptions carries the throughput-pack zstd settings. They mirror
// the already-committed config keys ZSTD_DICT_ENABLED, ZSTD_LEVEL and
// ZSTD_LONG_ENABLED. The zero value reproduces the pre-pack behavior
// exactly (SpeedFastest, no dictionary, default window); see
// Configure.
type ZSTDOptions struct {
	// DictEnabled enables the embedded shared dictionaries for zstd
	// encoding. Decoders always accept both dictionary and
	// dictionary-free frames once enabled. DictEnabled MUST be set
	// symmetrically on both ends of a tunnel running the same binary
	// version: a peer without it cannot decode dictionary frames
	// (unknown dictionary ID) and drops those packets. Enabling it
	// on one end only is a misconfiguration, not a negotiation.
	DictEnabled bool
	// Level selects the zstd level: 0 keeps the legacy SpeedFastest
	// encoder; 1..22 is mapped through
	// zstd.EncoderLevelFromZstd, which in klauspost/compress v1.18.5
	// only distinguishes four buckets (fastest <3, default 3-5,
	// better 6-9, best >=10). Out-of-range values are clamped.
	Level int
	// LongEnabled turns on the long window (see longWindowSize).
	LongEnabled bool
}

type zstdCodecSet struct {
	options         ZSTDOptions
	plainEncoder    *sync.Pool
	uploadEncoder   *sync.Pool
	downloadEncoder *sync.Pool
	decoder         *sync.Pool
}

var (
	zstdConfigMu   sync.RWMutex
	currentZstdSet = newZstdCodecSet(ZSTDOptions{})
)

func zstdEncoderOptions(opts ZSTDOptions, dict []byte) []zstd.EOption {
	level := zstd.SpeedFastest
	if opts.Level > 0 {
		level = zstd.EncoderLevelFromZstd(opts.Level)
	}
	options := []zstd.EOption{zstd.WithEncoderLevel(level)}
	if opts.LongEnabled {
		// WithWindowSize must follow WithEncoderLevel: the level
		// option sets a default window unless a custom window was
		// already requested.
		options = append(options, zstd.WithWindowSize(longWindowSize))
	}
	if dict != nil {
		options = append(options, zstd.WithEncoderDict(dict))
	}
	return options
}

func newZstdEncoderPool(opts ZSTDOptions, dict []byte) *sync.Pool {
	options := zstdEncoderOptions(opts, dict)
	return &sync.Pool{
		New: func() any {
			encoder, err := zstd.NewWriter(nil, options...)
			if err != nil {
				// Never pool a nil encoder; fall back to the
				// legacy construction. Dictionary frames are
				// still decodable by a dict-aware peer only
				// when the dict option applied, so this path
				// is fail-safe, not silent: a dict-less frame
				// simply compresses without the dictionary.
				encoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
			}
			return encoder
		},
	}
}

func newZstdCodecSet(opts ZSTDOptions) *zstdCodecSet {
	set := &zstdCodecSet{options: opts}
	set.plainEncoder = newZstdEncoderPool(opts, nil)
	if opts.DictEnabled {
		set.uploadEncoder = newZstdEncoderPool(opts, uploadDictionary)
		set.downloadEncoder = newZstdEncoderPool(opts, downloadDictionary)
	} else {
		set.uploadEncoder = set.plainEncoder
		set.downloadEncoder = set.plainEncoder
	}
	dictEnabled := opts.DictEnabled
	set.decoder = &sync.Pool{
		New: func() any {
			var decoder *zstd.Decoder
			var err error
			if dictEnabled {
				decoder, err = zstd.NewReader(nil, zstd.WithDecoderDicts(uploadDictionary, downloadDictionary))
			} else {
				decoder, err = zstd.NewReader(nil)
			}
			if err != nil || decoder == nil {
				decoder, _ = zstd.NewReader(nil)
			}
			return decoder
		},
	}
	return set
}

// Configure applies throughput-pack zstd settings process-wide. It is
// safe for concurrent use; encoder/decoder pools are rebuilt from the
// new settings, so frames already encoded with older settings remain
// decodable (the decoder accepts dictionary and dictionary-free
// frames alike once dictionaries are enabled, and dictionary-free
// frames always). Configure is normally called once at startup by the
// coordinator that owns the config; calling it per frame would
// rebuild the pools every time. The zero value restores the legacy
// behavior byte-for-byte (see TestCompressPayloadGoldenByteIdentity).
func Configure(opts ZSTDOptions) {
	if opts.Level < 0 {
		opts.Level = 0
	}
	if opts.Level > 22 {
		opts.Level = 22
	}
	zstdConfigMu.Lock()
	defer zstdConfigMu.Unlock()
	currentZstdSet = newZstdCodecSet(opts)
}

func currentZSTDOptions() ZSTDOptions {
	zstdConfigMu.RLock()
	defer zstdConfigMu.RUnlock()
	return currentZstdSet.options
}

func getZstdCodecSet() *zstdCodecSet {
	zstdConfigMu.RLock()
	defer zstdConfigMu.RUnlock()
	return currentZstdSet
}

// CompressPayloadForDirection is CompressPayload with an explicit
// dictionary choice for zstd encoding. It exists for call sites that
// know the traffic direction (upload = requests, download =
// responses) so each direction can use its own trained dictionary
// with a single encode. CompressPayload itself cannot know the
// direction, so with dictionaries enabled it encodes with both
// dictionaries and keeps the smaller frame. The compression-type
// negotiation, entropy gate, min-size gate and size check are
// identical to CompressPayload.
func CompressPayloadForDirection(data []byte, compType uint8, minSize int, dict Dictionary) ([]byte, uint8) {
	return compressPayload(data, compType, minSize, dict, false)
}

func compressPayload(data []byte, compType uint8, minSize int, dict Dictionary, autoDict bool) ([]byte, uint8) {
	if len(data) == 0 {
		return data, TypeOff
	}

	compType = NormalizeAvailableType(compType)
	if compType == TypeOff {
		return data, TypeOff
	}
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if len(data) <= minSize {
		return data, TypeOff
	}
	// TLS, QUIC and media payloads are commonly already compressed. A cheap
	// entropy sample avoids running a full codec when there is virtually no
	// compressible structure, reducing latency and battery use on native clients.
	if payloadEntropyBits(data) >= 7.6 {
		return data, TypeOff
	}

	var compData []byte
	var err error

	switch compType {
	case TypeZLIB:
		compData, err = compressZLIB(data)
	case TypeZSTD:
		compData, err = compressZSTDChoice(data, dict, autoDict)
	case TypeLZ4:
		compData, err = compressLZ4(data)
	}

	if err != nil {
		return data, TypeOff
	}
	if len(compData) >= len(data) {
		return data, TypeOff
	}

	return compData, compType
}
