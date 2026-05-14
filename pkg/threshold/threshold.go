package threshold

import (
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Keygen runs distributed key generation for partyCount parties with the given threshold.
// All parties run in-process. Returns one LocalPartySaveData per party — needed for signing.
func Keygen(partyCount, threshold int) ([]keygen.LocalPartySaveData, error) {
	partyIDs := tss.GenerateTestPartyIDs(partyCount)
	ctx := tss.NewPeerContext(partyIDs)

	errCh := make(chan *tss.Error, partyCount)
	outCh := make(chan tss.Message, partyCount*partyCount)
	endCh := make(chan *keygen.LocalPartySaveData, partyCount)

	parties := make([]tss.Party, partyCount)
	for i, id := range partyIDs {
		params := tss.NewParameters(tss.S256(), ctx, id, partyCount, threshold)
		parties[i] = keygen.NewLocalParty(params, outCh, endCh)
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(parties[i])
	}

	saves := make([]keygen.LocalPartySaveData, partyCount)
	var done int32
	for {
		select {
		case err := <-errCh:
			return nil, fmt.Errorf("keygen: %v", err)

		case msg := <-outCh:
			route(msg, parties, errCh)

		case save := <-endCh:
			idx, err := save.OriginalIndex()
			if err != nil {
				return nil, fmt.Errorf("keygen index: %w", err)
			}
			saves[idx] = *save
			if atomic.AddInt32(&done, 1) == int32(partyCount) {
				return saves, nil
			}
		}
	}
}

// Sign produces a threshold ECDSA signature over msgHash.
// keys must be the full slice from Keygen; threshold+1 parties will participate.
func Sign(msgHash []byte, keys []keygen.LocalPartySaveData, threshold int) (*common.SignatureData, error) {
	signerCount := threshold + 1
	if len(keys) < signerCount {
		return nil, fmt.Errorf("need at least %d keys, got %d", signerCount, len(keys))
	}

	// Use the first signerCount parties
	signerIDs := tss.GenerateTestPartyIDs(len(keys))[:signerCount]
	signerIDs = tss.SortPartyIDs(tss.UnSortedPartyIDs(signerIDs))
	ctx := tss.NewPeerContext(signerIDs)
	m := new(big.Int).SetBytes(msgHash)

	errCh := make(chan *tss.Error, signerCount)
	outCh := make(chan tss.Message, signerCount*signerCount)
	endCh := make(chan *common.SignatureData, signerCount)

	parties := make([]tss.Party, signerCount)
	for i, id := range signerIDs {
		params := tss.NewParameters(tss.S256(), ctx, id, signerCount, threshold)
		parties[i] = signing.NewLocalParty(m, params, keys[i], outCh, endCh)
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(parties[i])
	}

	for {
		select {
		case err := <-errCh:
			return nil, fmt.Errorf("sign: %v", err)

		case msg := <-outCh:
			route(msg, parties, errCh)

		case sig := <-endCh:
			return sig, nil
		}
	}
}

// route delivers a tss message to the correct party or parties.
// Broadcast messages go to everyone except the sender; P2P messages go to a single recipient.
func route(msg tss.Message, parties []tss.Party, errCh chan<- *tss.Error) {
	dest := msg.GetTo()
	if dest == nil {
		// broadcast
		for _, p := range parties {
			if p.PartyID().Index == msg.GetFrom().Index {
				continue
			}
			go deliver(p, msg, errCh)
		}
	} else {
		// point-to-point
		go deliver(parties[dest[0].Index], msg, errCh)
	}
}

// deliver serialises and re-parses a message before calling Update,
// matching how a real network transport would work.
func deliver(p tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- p.WrapError(err)
		return
	}
	parsed, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- p.WrapError(err)
		return
	}
	if _, tssErr := p.Update(parsed); tssErr != nil {
		errCh <- tssErr
	}
}
