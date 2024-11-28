package types

type TxPoolInfo struct {
	LastTxsUpdatedAt uint64 `json:"last_txs_updated_at"`
	MaxTxPoolSize    uint64 `json:"max_tx_pool_size"`
	MinFeeRate       uint64 `json:"min_fee_rate"`
	MinRbfRate       uint64 `json:"min_fee_rate"`
	Orphan           uint64 `json:"orphan"`
	Pending          uint64 `json:"pending"`
	Proposed         uint64 `json:"proposed"`
	TipHash          Hash   `json:"tip_hash"`
	TipNumber        uint64 `json:"tip_number"`
	TotalTxCycles    uint64 `json:"total_tx_cycles"`
	TotalTxSize      uint64 `json:"total_tx_size"`
	TxSizeLimit      uint64 `json:"tx_size_limit"`
	VerifyQueueSize  uint64 `json:"verify_queue_size"`
}

type RawTxPool struct {
	Pending  []Hash `json:"pending"`
	Proposed []Hash `json:"proposed"`
}

type AncestorsScoreSortKey struct {
	AncestorsFee    uint64 `json:"ancestors_fee"`
	AncestorsWeight uint64 `json:"ancestors_weight"`
	Fee             uint64 `json:"fee"`
	Weight          uint64 `json:"weight"`
}

type PoolTxDetailInfo struct {
	AncestorsCount   uint64                `json:"ancestors_count"`
	DescendantsCount uint64                `json:"descendants_count"`
	EntryStatus      string                `json:"entry_status"`
	PendingCount     uint64                `json:"pending_count"`
	ProposedCount    uint64                `json:"proposed_count"`
	RankInPending    uint64                `json:"rank_in_pending"`
	ScoreSortKey     AncestorsScoreSortKey `json:"score_sortkey"`
	Timestamp        uint64                `json:"timestamp"`
}

type EntryCompleted struct {
	// Cached tx cycles
	cycles uint64 `json:"cycles"`
	// Cached tx fee
	fee uint64 `json:"fee"`
}
