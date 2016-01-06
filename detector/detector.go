package detector

import (
	"bytes"
	"gopkg.in/h2non/bimg.v0"
)

// The algorithm uses at most sniffLen bytes to make its decision.
const sniffLen = 512

type Format struct {
	Mime  string
	Extra string
}

type sniffSig interface {
	// match returns the MIME type of the data, or "" if unknown.
	match(data []byte, firstNonWS int) Format
}

// DetectContentType implements the algorithm described
// at http://mimesniff.spec.whatwg.org/ to determine the
// Content-Type of the given data.  It considers at most the
// first 512 bytes of data.  DetectContentType always returns
// a valid MIME type: if it cannot determine a more specific one, it
// returns "application/octet-stream".
func DetectContentType(data []byte) Format {
	if len(data) > sniffLen {
		data = data[:sniffLen]
	}

	// Index of the first non-whitespace byte in data.
	firstNonWS := 0
	for ; firstNonWS < len(data) && isWS(data[firstNonWS]); firstNonWS++ {
	}

	for _, sig := range sniffSignatures {
		if ct := sig.match(data, firstNonWS); ct.Mime != "" {
			return ct
		}
	}

	return Format{
		Mime:  "application/octet-stream", // fallback
		Extra: "",
	}
}

// Data matching the table in section 6.
var sniffSignatures = []sniffSig{
	htmlSig("<!DOCTYPE HTML"),
	htmlSig("<HTML"),
	htmlSig("<HEAD"),
	htmlSig("<SCRIPT"),
	htmlSig("<IFRAME"),
	htmlSig("<H1"),
	htmlSig("<DIV"),
	htmlSig("<FONT"),
	htmlSig("<TABLE"),
	htmlSig("<A"),
	htmlSig("<STYLE"),
	htmlSig("<TITLE"),
	htmlSig("<B"),
	htmlSig("<BODY"),
	htmlSig("<BR"),
	htmlSig("<P"),
	htmlSig("<!--"),

	&maskedSig{mask: []byte("\xFF\xFF\xFF\xFF\xFF"), pat: []byte("<?xml"), skipWS: true, ct: "text/xml; charset=utf-8", extra: "xml"},

	// PSD format => http://www.adobe.com/devnet-apps/photoshop/fileformatashtml/#50577409_pgfId-1055726
	&exactSig{[]byte("\x38\x42\x50\x53\x00\x01\x00\x00\x00\x00\x00\x00"), "application/octet-stream", "psd"},

	&exactSig{[]byte("%PDF-"), "application/pdf", "pdf"},
	&exactSig{[]byte("%!PS-Adobe-"), "application/postscript", "postscript"},

	// UTF BOMs.
	&maskedSig{mask: []byte("\xFF\xFF\x00\x00"), pat: []byte("\xFE\xFF\x00\x00"), ct: "text/plain; charset=utf-16be", extra: "txt"},
	&maskedSig{mask: []byte("\xFF\xFF\x00\x00"), pat: []byte("\xFF\xFE\x00\x00"), ct: "text/plain; charset=utf-16le", extra: "txt"},
	&maskedSig{mask: []byte("\xFF\xFF\xFF\x00"), pat: []byte("\xEF\xBB\xBF\x00"), ct: "text/plain; charset=utf-8", extra: "txt"},

	&exactSig{[]byte("GIF87a"), "image/gif", "gif"},
	&exactSig{[]byte("GIF89a"), "image/gif", "gif"},
	&exactSig{[]byte("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"), "image/png", bimg.ImageTypes[bimg.PNG]},
	&exactSig{[]byte("\xFF\xD8\xFF"), "image/jpeg", bimg.ImageTypes[bimg.JPEG]},
	&exactSig{[]byte("BM"), "image/bmp", "bmp"},
	&maskedSig{
		mask:  []byte("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF"),
		pat:   []byte("RIFF\x00\x00\x00\x00WEBPVP"),
		ct:    "image/webp",
		extra: "webp",
	},
	&exactSig{[]byte("\x00\x00\x01\x00"), "image/vnd.microsoft.icon", "ico"},
	&exactSig{[]byte("\x4F\x67\x67\x53\x00"), "application/ogg", "ogg"},
	&maskedSig{
		mask:  []byte("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"),
		pat:   []byte("RIFF\x00\x00\x00\x00WAVE"),
		ct:    "audio/wave",
		extra: "wav",
	},
	&exactSig{[]byte("\x1A\x45\xDF\xA3"), "video/webm", "webm"},
	&exactSig{[]byte("\x52\x61\x72\x20\x1A\x07\x00"), "application/x-rar-compressed", "rar"},
	&exactSig{[]byte("\x50\x4B\x03\x04"), "application/zip", "zip"},
	&exactSig{[]byte("\x1F\x8B\x08"), "application/x-gzip", "gzip"},

	// TODO(dsymonds): Re-enable this when the spec is sorted w.r.t. MP4.
	//mp4Sig(0),

	textSig(0), // should be last
}

func isWS(b byte) bool {
	return bytes.IndexByte([]byte("\t\n\x0C\r "), b) != -1
}

type exactSig struct {
	sig   []byte
	ct    string
	extra string
}

func (e *exactSig) match(data []byte, firstNonWS int) Format {
	if bytes.HasPrefix(data, e.sig) {
		return Format{
			Mime:  e.ct,
			Extra: e.extra,
		}
	}
	return Format{}
}

type maskedSig struct {
	mask, pat []byte
	skipWS    bool
	ct        string
	extra     string
}

func (m *maskedSig) match(data []byte, firstNonWS int) Format {
	if m.skipWS {
		data = data[firstNonWS:]
	}
	if len(data) < len(m.mask) {
		return Format{}
	}
	for i, mask := range m.mask {
		db := data[i] & mask
		if db != m.pat[i] {
			return Format{}
		}
	}
	return Format{
		Mime:  m.ct,
		Extra: "",
	}
}

type htmlSig []byte

func (h htmlSig) match(data []byte, firstNonWS int) Format {
	data = data[firstNonWS:]
	if len(data) < len(h)+1 {
		return Format{}
	}
	for i, b := range h {
		db := data[i]
		if 'A' <= b && b <= 'Z' {
			db &= 0xDF
		}
		if b != db {
			return Format{}
		}
	}
	// Next byte must be space or right angle bracket.
	if db := data[len(h)]; db != ' ' && db != '>' {
		return Format{}
	}
	return Format{
		Mime:  "text/html; charset=utf-8",
		Extra: "",
	}
}

type textSig int

func (textSig) match(data []byte, firstNonWS int) Format {
	// c.f. section 5, step 4.
	for _, b := range data[firstNonWS:] {
		switch {
		case 0x00 <= b && b <= 0x08,
			b == 0x0B,
			0x0E <= b && b <= 0x1A,
			0x1C <= b && b <= 0x1F:
			return Format{}
		}
	}
	return Format{
		Mime:  "text/plain; charset=utf-8",
		Extra: "",
	}
}
