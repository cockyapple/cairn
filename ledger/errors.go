package ledger

import "errors"

// Stable, machine-readable failure codes. Test vectors assert on these, so
// they are part of the spec and must not be renamed.
const (
	CodeBadLength        = "bad_length"
	CodeBadVersion       = "bad_version"
	CodeUnknownKind      = "unknown_kind"
	CodeBadGenesis       = "bad_genesis"
	CodeDuplicateGenesis = "duplicate_genesis"
	CodeBadHeight        = "bad_height"
	CodeBadPrevHash      = "bad_prev_hash"
	CodeBadSignature     = "bad_signature"
	CodeBadPayload       = "bad_payload"

	CodeSizeMismatch     = "size_mismatch"
	CodeRootMismatch     = "root_mismatch"
	CodeHeadMismatch     = "head_mismatch"
	CodeEpochMismatch    = "epoch_mismatch"
	CodeBelowQuorum      = "below_quorum"
	CodeBelowWitnesses   = "below_witness_threshold"
	CodeDuplicateSigner  = "duplicate_signer"
	CodeBadTrustConfig   = "bad_trust_config"
	CodeBadCheckpointLen = "bad_checkpoint"
)

type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func fail(code, detail string) error { return &Error{Code: code, Detail: detail} }

// ErrCode returns the stable code of err, or "" if err is nil or not a ledger error.
func ErrCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
