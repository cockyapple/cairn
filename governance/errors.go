package governance

import (
	"errors"
	"fmt"

	"github.com/cockyapple/cairn/ledger"
)

// Stable failure codes for the governance rules (SPEC section 10). Payload
// decoding failures keep the ledger codes (bad_payload, bad_trust_config).
const (
	CodeUnauthorizedAuthor    = "unauthorized_author"
	CodeBadBlob               = "bad_blob"
	CodeTimeRegression        = "time_regression"
	CodeConstitutionMismatch  = "constitution_mismatch"
	CodeReservedTarget        = "reserved_target"
	CodeUnknownProposal       = "unknown_proposal"
	CodeWrongEpoch            = "wrong_epoch"
	CodeDuplicateVote         = "duplicate_vote"
	CodeAlreadyActivated      = "already_activated"
	CodeBadVoteReference      = "bad_vote_reference"
	CodeBlockedByVote         = "blocked_by_vote"
	CodeInsufficientApprovals = "insufficient_approvals"
	CodeDelayTooShort         = "delay_too_short"
	CodeDelayNotElapsed       = "delay_not_elapsed"
	CodeFrozen                = "frozen"
	CodeBadFreezeState        = "bad_freeze_state"
	CodeBadValidatorsChange   = "bad_validators_change"
	CodeBadActionChain        = "bad_action_chain"
	CodeBadActionCompletion   = "bad_action_completion"
	CodeTierTooLow            = "tier_too_low"
	CodeFutureEntry           = "future_entry"
	CodeBadRevocation         = "bad_revocation"
	CodeRevokedKey            = "revoked_key"
	CodeBadGrant              = "bad_grant"
	CodeBadDelegation         = "bad_delegation"
	CodeNotNarrower           = "delegation_not_narrower"
)

// AllCodes lists every governance code; a test requires SPEC section 10 to match.
var AllCodes = []string{
	CodeUnauthorizedAuthor, CodeBadBlob, CodeTimeRegression, CodeConstitutionMismatch,
	CodeReservedTarget, CodeUnknownProposal, CodeWrongEpoch, CodeDuplicateVote,
	CodeAlreadyActivated, CodeBadVoteReference, CodeBlockedByVote, CodeInsufficientApprovals,
	CodeDelayTooShort, CodeDelayNotElapsed, CodeFrozen, CodeBadFreezeState,
	CodeBadValidatorsChange, CodeBadActionChain, CodeBadActionCompletion,
	CodeTierTooLow, CodeFutureEntry, CodeBadRevocation, CodeRevokedKey,
	CodeBadGrant, CodeBadDelegation, CodeNotNarrower,
}

// Error is a governance violation at a specific entry.
type Error struct {
	Code   string
	Height uint64
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("%s at height %d: %s", e.Code, e.Height, e.Detail) }

// ErrCode returns the stable code of a governance or ledger error, else "".
func ErrCode(err error) string {
	var g *Error
	if errors.As(err, &g) {
		return g.Code
	}
	return ledger.ErrCode(err)
}

func fail(height uint64, code, detail string) error {
	return &Error{Code: code, Height: height, Detail: detail}
}

// decodeFail keeps the ledger's code for a malformed payload.
func decodeFail(height uint64, err error) error {
	return &Error{Code: ledger.ErrCode(err), Height: height, Detail: err.Error()}
}
