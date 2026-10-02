// Package note renders a Cairn checkpoint as a C2SP signed note, so outside
// witnesses and monitors that speak the transparency-log ecosystem's format can
// consume a Cairn log without learning Cairn's wire format.
//
// The native binary checkpoint stays the object Cairn itself signs and
// verifies. A note is a second, independent signature over the same tree head,
// made by the same keys. It uses the plain three-line tlog-checkpoint body
// (origin, size, root) with no extension lines: epoch and head hash are
// derivable from the log, so nothing Cairn-specific rides in the note.
//
// Validators sign as C2SP Ed25519 note signatures (type 0x01) under the log's
// origin. Witnesses cosign (type 0x04, tlog-cosignature) under a name each
// chooses. See docs/SPEC-NOTE.md. Standard library only.
package note

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cockyapple/cairn/ledger"
)

const (
	SigEd25519     = 0x01
	SigCosignature = 0x04

	maxNote     = 256 << 10
	maxSigLines = 1024
	maxOrigin   = 255
	sigPrefix   = "— "

	cosigDomain = "cosignature/v1\ntime "
)

// Stable failure codes. Codes shared with the native checkpoint reuse the
// ledger's strings.
const (
	CodeBadNote        = "bad_note"
	CodeBadOrigin      = "bad_origin"
	CodeOriginMismatch = "origin_mismatch"
)

func fail(code, detail string) error { return &ledger.Error{Code: code, Detail: detail} }

// Config says who the verifier believes it is looking at.
type Config struct {
	// Origin names the log. Validators sign under this name.
	Origin string
	// WitnessNames maps each admitted witness key to the name it cosigns under.
	// A witness with no entry here is not usable for this verification.
	WitnessNames map[[32]byte]string
}

// Result is what a verified note commits to.
type Result struct {
	Size       uint64
	Root       ledger.Hash
	Validators int
	Witnesses  int
}

// validName reports whether s is acceptable as a note key name and as an
// origin: non-empty, UTF-8, no Unicode spaces or controls, and no '+'.
func validName(s string) bool {
	if s == "" || len(s) > maxOrigin || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '+' {
			return false
		}
	}
	return true
}

// KeyID is the 4-byte identifier C2SP derives from a key's name, signature
// type and public key.
func KeyID(name string, sigType byte, pub [32]byte) [4]byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', sigType})
	h.Write(pub[:])
	var id [4]byte
	copy(id[:], h.Sum(nil))
	return id
}

// VKey renders a verifier key in the C2SP "name+keyid+base64(type||pub)" form.
func VKey(name string, sigType byte, pub [32]byte) (string, error) {
	if !validName(name) {
		return "", fail(CodeBadOrigin, "key name is empty or contains a space, control character or '+'")
	}
	id := KeyID(name, sigType, pub)
	return name + "+" + hex.EncodeToString(id[:]) + "+" + base64.StdEncoding.EncodeToString(append([]byte{sigType}, pub[:]...)), nil
}

// ParseVKey is the inverse of VKey. It rejects a key whose stated id does not
// match the name, type and public key.
func ParseVKey(s string) (name string, sigType byte, pub [32]byte, err error) {
	parts := strings.Split(s, "+")
	if len(parts) != 3 || !validName(parts[0]) {
		return "", 0, pub, fail(CodeBadNote, "malformed verifier key")
	}
	idb, err := hex.DecodeString(parts[1])
	if err != nil || len(idb) != 4 || hex.EncodeToString(idb) != parts[1] {
		return "", 0, pub, fail(CodeBadNote, "malformed key id")
	}
	kb, err := b64(parts[2])
	if err != nil || len(kb) != 33 {
		return "", 0, pub, fail(CodeBadNote, "malformed key material")
	}
	sigType = kb[0]
	copy(pub[:], kb[1:])
	if id := KeyID(parts[0], sigType, pub); !bytes.Equal(id[:], idb) {
		return "", 0, pub, fail(CodeBadNote, "key id does not match the key")
	}
	return parts[0], sigType, pub, nil
}

// b64 decodes standard padded base64 and rejects any non-canonical form.
func b64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("non-canonical base64")
	}
	return b, nil
}

// Text is the tlog-checkpoint body for a tree head: origin, size, root.
func Text(origin string, size uint64, root ledger.Hash) ([]byte, error) {
	if !validName(origin) {
		return nil, fail(CodeBadOrigin, "origin is empty, too long, or not a valid key name")
	}
	if size == 0 {
		return nil, fail(CodeBadNote, "an empty log has no checkpoint")
	}
	return []byte(origin + "\n" + strconv.FormatUint(size, 10) + "\n" + base64.StdEncoding.EncodeToString(root[:]) + "\n"), nil
}

// parseText is the strict inverse of Text. Extension lines are rejected, so
// one tree head has exactly one text.
func parseText(text []byte) (origin string, size uint64, root ledger.Hash, err error) {
	lines := strings.Split(string(text), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return "", 0, root, fail(CodeBadNote, "checkpoint text must be exactly origin, size and root")
	}
	if !validName(lines[0]) {
		return "", 0, root, fail(CodeBadOrigin, "origin is empty, too long, or not a valid key name")
	}
	size, perr := strconv.ParseUint(lines[1], 10, 64)
	if perr != nil || size == 0 || strconv.FormatUint(size, 10) != lines[1] {
		return "", 0, root, fail(CodeBadNote, "size is not a canonical positive decimal")
	}
	rb, berr := b64(lines[2])
	if berr != nil || len(rb) != 32 {
		return "", 0, root, fail(CodeBadNote, "root is not canonical base64 of 32 bytes")
	}
	copy(root[:], rb)
	return lines[0], size, root, nil
}

// splitNote separates the signed text from its signature lines. The text is
// everything up to the last blank line.
func splitNote(raw []byte) (text []byte, lines []string, err error) {
	if len(raw) > maxNote {
		return nil, nil, fail(CodeBadNote, "note is too large")
	}
	if !utf8.Valid(raw) {
		return nil, nil, fail(CodeBadNote, "note is not valid UTF-8")
	}
	for _, r := range string(raw) {
		if unicode.IsControl(r) && r != '\n' {
			return nil, nil, fail(CodeBadNote, "note contains a control character")
		}
	}
	i := bytes.LastIndex(raw, []byte("\n\n"))
	if i < 0 {
		return nil, nil, fail(CodeBadNote, "no blank line between text and signatures")
	}
	text, block := raw[:i+1], raw[i+2:]
	if len(block) == 0 || block[len(block)-1] != '\n' {
		return nil, nil, fail(CodeBadNote, "no signature lines, or the last one is unterminated")
	}
	lines = strings.Split(string(block[:len(block)-1]), "\n")
	if len(lines) > maxSigLines {
		return nil, nil, fail(CodeBadNote, "too many signature lines")
	}
	return text, lines, nil
}

// parseSigLine returns the signer name and the decoded payload (4-byte key id
// followed by the signature body).
func parseSigLine(l string) (name string, payload []byte, err error) {
	rest, ok := strings.CutPrefix(l, sigPrefix)
	if !ok {
		return "", nil, fail(CodeBadNote, "signature line does not begin with an em dash and a space")
	}
	parts := strings.Split(rest, " ")
	if len(parts) != 2 || !validName(parts[0]) {
		return "", nil, fail(CodeBadNote, "malformed signature line")
	}
	payload, berr := b64(parts[1])
	if berr != nil || len(payload) < 4 {
		return "", nil, fail(CodeBadNote, "signature is not canonical base64 of at least 4 bytes")
	}
	return parts[0], payload, nil
}

// Peek reads the tree head from a note without checking any signature. It
// exists only so a caller can pick the trust configuration for that size;
// nothing it returns is authenticated until Verify succeeds.
func Peek(raw []byte) (origin string, size uint64, root ledger.Hash, err error) {
	text, _, err := splitNote(raw)
	if err != nil {
		return "", 0, root, err
	}
	return parseText(text)
}

func cosigMessage(ts uint64, text []byte) []byte {
	return append([]byte(cosigDomain+strconv.FormatUint(ts, 10)+"\n"), text...)
}

func line(name string, id [4]byte, body []byte) string {
	return sigPrefix + name + " " + base64.StdEncoding.EncodeToString(append(id[:], body...)) + "\n"
}

func checkKey(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fail(CodeBadNote, "malformed private key")
	}
	return nil
}

// SignValidator signs text as a validator would, under the log's origin.
func SignValidator(priv ed25519.PrivateKey, origin string, text []byte) (string, error) {
	if err := checkKey(priv); err != nil {
		return "", err
	}
	if !validName(origin) {
		return "", fail(CodeBadOrigin, "origin is not a valid key name")
	}
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return line(origin, KeyID(origin, SigEd25519, pub), ed25519.Sign(priv, text)), nil
}

// Cosign signs text as a witness, under name, at unix time ts. C2SP's
// cosignature does not commit to the name, so a witness operator should use a
// distinct key for each name it cosigns under.
func Cosign(priv ed25519.PrivateKey, name string, ts uint64, text []byte) (string, error) {
	if err := checkKey(priv); err != nil {
		return "", err
	}
	if !validName(name) {
		return "", fail(CodeBadOrigin, "witness name is not a valid key name")
	}
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	body := binary.BigEndian.AppendUint64(nil, ts)
	body = append(body, ed25519.Sign(priv, cosigMessage(ts, text))...)
	return line(name, KeyID(name, SigCosignature, pub), body), nil
}

// Assemble joins text and signature lines into a note. Lines are sorted so the
// same set of signatures always yields the same bytes.
func Assemble(text []byte, lines ...string) ([]byte, error) {
	if _, _, _, err := parseText(text); err != nil {
		return nil, err
	}
	if len(lines) == 0 || len(lines) > maxSigLines {
		return nil, fail(CodeBadNote, "a note needs between 1 and 1024 signature lines")
	}
	ls := append([]string(nil), lines...)
	sort.Strings(ls)
	out := append(append([]byte(nil), text...), '\n')
	for _, l := range ls {
		if !strings.HasPrefix(l, sigPrefix) || !strings.HasSuffix(l, "\n") || strings.Count(l, "\n") != 1 {
			return nil, fail(CodeBadNote, "malformed signature line")
		}
		out = append(out, l...)
	}
	return out, nil
}

type slot struct {
	name string
	id   [4]byte
}

type signer struct {
	pub  [32]byte
	role ledger.Role
}

// Verify checks a note against the trust configuration in force for its size.
// It enforces the validator quorum and the witness threshold with the same
// arithmetic as the native checkpoint. As C2SP requires, signatures by keys
// the verifier does not know are ignored, but a signature by a known key that
// fails to verify rejects the whole note, and a key may count only once.
// Cosignature timestamps are not judged: freshness is the relying party's
// policy. The note does not carry the epoch; the caller supplies the trust
// configuration for the epoch it intends.
func Verify(raw []byte, cfg Config, trust *ledger.TrustConfig) (Result, error) {
	var res Result
	if trust == nil {
		return res, fail(ledger.CodeBadTrustConfig, "no trust configuration supplied")
	}
	if err := trust.Validate(); err != nil {
		return res, err
	}
	if !validName(cfg.Origin) {
		return res, fail(CodeBadOrigin, "configured origin is not a valid key name")
	}
	text, lines, err := splitNote(raw)
	if err != nil {
		return res, err
	}
	origin, size, root, err := parseText(text)
	if err != nil {
		return res, err
	}
	if origin != cfg.Origin {
		return res, fail(CodeOriginMismatch, "note is for a different log")
	}
	res.Size, res.Root = size, root

	table := map[slot][]signer{}
	validators := 0
	for _, k := range trust.Keys {
		switch k.Role {
		case ledger.RoleValidator:
			validators++
			s := slot{cfg.Origin, KeyID(cfg.Origin, SigEd25519, k.Public)}
			table[s] = append(table[s], signer{k.Public, k.Role})
		case ledger.RoleWitness:
			if n, ok := cfg.WitnessNames[k.Public]; ok && validName(n) {
				s := slot{n, KeyID(n, SigCosignature, k.Public)}
				table[s] = append(table[s], signer{k.Public, k.Role})
			}
		}
	}

	seen := map[[32]byte]bool{}
	for _, l := range lines {
		name, payload, err := parseSigLine(l)
		if err != nil {
			return res, err
		}
		var id [4]byte
		copy(id[:], payload)
		cands := table[slot{name, id}]
		if len(cands) == 0 {
			continue
		}
		var matched *signer
		for i := range cands {
			if sigOK(cands[i], payload[4:], text) {
				matched = &cands[i]
				break
			}
		}
		if matched == nil {
			return res, fail(ledger.CodeBadSignature, "invalid signature by a known key")
		}
		if seen[matched.pub] {
			return res, fail(ledger.CodeDuplicateSigner, "a key signed more than once")
		}
		seen[matched.pub] = true
		if matched.role == ledger.RoleValidator {
			res.Validators++
		} else {
			res.Witnesses++
		}
	}
	if res.Validators < ledger.ValidatorQuorum(validators) {
		return res, fail(ledger.CodeBelowQuorum, "not enough validator signatures")
	}
	if res.Witnesses < int(trust.WitnessThreshold) {
		return res, fail(ledger.CodeBelowWitnesses, "not enough witness cosignatures")
	}
	return res, nil
}

func sigOK(s signer, body, text []byte) bool {
	pub := ed25519.PublicKey(s.pub[:])
	if s.role == ledger.RoleValidator {
		return len(body) == ed25519.SignatureSize && ed25519.Verify(pub, text, body)
	}
	if len(body) != 8+ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, cosigMessage(binary.BigEndian.Uint64(body[:8]), text), body[8:])
}

// VerifyLog is the full check an outside party runs on a note: the chain is
// sound, the note's signatures meet quorum, and its tree head is the one the
// entries actually produce. trust must be the configuration in force after
// entry size-1.
func VerifyLog(entries []ledger.Entry, raw []byte, cfg Config, trust *ledger.TrustConfig) (Result, error) {
	if err := ledger.VerifyChain(entries); err != nil {
		return Result{}, err
	}
	res, err := Verify(raw, cfg, trust)
	if err != nil {
		return res, err
	}
	if res.Size != uint64(len(entries)) {
		return res, fail(ledger.CodeSizeMismatch, "note size does not match the entries supplied")
	}
	if res.Root != ledger.LogRoot(entries) {
		return res, fail(ledger.CodeRootMismatch, "merkle root differs from the entries")
	}
	return res, nil
}
