package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// TokenFreezeStatus is the status of a token leaf.
type TokenFreezeStatus string

const (
	// TokenFreezeStatusCreating is the default status once a freeze has been applied.
	TokenFreezeStatusFrozen TokenFreezeStatus = "FROZEN"
	// TokenFreezeStatusThawed is the status after a prior freeze was removed.
	TokenFreezeStatusThawed TokenFreezeStatus = "THAWED"
)

// Values returns the values of the token leaf status.
func (TokenFreezeStatus) Values() []string {
	return []string{
		string(TokenFreezeStatusFrozen),
		string(TokenFreezeStatusThawed),
	}
}

// TokenFreeze is the schema for the token leafs table.
type TokenFreeze struct {
	ent.Schema
}

// Mixin is the mixin for the token leafs table.
func (TokenFreeze) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields are the fields for the token leafs table.
func (TokenFreeze) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("status").GoType(TokenFreezeStatus("")),
		field.Bytes("owner_public_key").NotEmpty().Immutable(),
		field.Bytes("token_public_key").NotEmpty().Immutable(),
		field.Bytes("issuer_signature").NotEmpty().Immutable().Unique(),
		field.Uint64("wallet_provided_freeze_timestamp").Immutable(),
		field.Uint64("wallet_provided_thaw_timestamp").Optional(),
	}
}

// Edges are the edges for the token leafs table.
func (TokenFreeze) Edges() []ent.Edge {
	return []ent.Edge{}
}

// Indexes are the indexes for the token leafs table.
func (TokenFreeze) Indexes() []ent.Index {
	return []ent.Index{
		// Enforce uniqueness to ensure idempotency.
		index.Fields("owner_public_key", "token_public_key", "wallet_provided_freeze_timestamp").Unique().
			StorageKey("tokenfreeze_owner_public_key_token_public_key_wallet_provided_f"),
		index.Fields("owner_public_key", "token_public_key", "wallet_provided_thaw_timestamp").Unique().
			StorageKey("tokenfreeze_owner_public_key_token_public_key_wallet_provided_t"),
	}
}
