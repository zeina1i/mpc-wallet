package dkg

import (
	"testing"
)

// runDKG simulates the full DKG protocol for n participants with threshold t.
func runDKG(t *testing.T, threshold, total int) []*DKGResult {
	t.Helper()
	seed := []byte("shared-pedersen-seed")

	// Create participants
	participants := make([]*ParticipantImpl, total)
	for i := 0; i < total; i++ {
		p, err := NewParticipant(ParticipantID(i+1), threshold, total, seed)
		if err != nil {
			t.Fatalf("NewParticipant %d: %v", i+1, err)
		}
		participants[i] = p
	}

	// Round 1: each participant creates broadcast + shares
	broadcasts := make([]*Round1Broadcast, total)
	allShares := make([]map[ParticipantID]*Round1Share, total)
	for i, p := range participants {
		bc, shares, err := p.Round1()
		if err != nil {
			t.Fatalf("participant %d Round1: %v", i+1, err)
		}
		broadcasts[i] = bc
		allShares[i] = shares
	}

	// Distribute broadcasts and shares
	for _, p := range participants {
		for _, bc := range broadcasts {
			if bc.SenderID == p.GetID() {
				continue // skip own
			}
			if err := p.ProcessBroadcast(bc); err != nil {
				t.Fatalf("participant %d ProcessBroadcast from %d: %v", p.GetID(), bc.SenderID, err)
			}
		}
		for senderIdx, shares := range allShares {
			senderID := ParticipantID(senderIdx + 1)
			if senderID == p.GetID() {
				continue // skip own
			}
			if err := p.ProcessShare(shares[p.GetID()]); err != nil {
				t.Fatalf("participant %d ProcessShare from %d: %v", p.GetID(), senderID, err)
			}
		}
	}

	// Round 2: compute final shares
	results := make([]*DKGResult, total)
	for i, p := range participants {
		res, err := p.Round2()
		if err != nil {
			t.Fatalf("participant %d Round2: %v", i+1, err)
		}
		results[i] = res
	}

	return results
}

func TestDKG_GroupPublicKeyConsistent(t *testing.T) {
	results := runDKG(t, 2, 3)

	// All participants must derive the same group public key
	ref := results[0].GroupPublicKey
	for _, r := range results[1:] {
		if r.GroupPublicKey.X.Cmp(ref.X) != 0 || r.GroupPublicKey.Y.Cmp(ref.Y) != 0 {
			t.Fatalf("participant %d has different group public key", r.ParticipantID)
		}
	}
}

func TestDKG_ShareIndices(t *testing.T) {
	results := runDKG(t, 2, 3)
	for _, r := range results {
		if r.FinalShare.Index != int(r.ParticipantID) {
			t.Fatalf("participant %d has share index %d", r.ParticipantID, r.FinalShare.Index)
		}
	}
}

func TestDKG_ThresholdMetadata(t *testing.T) {
	results := runDKG(t, 2, 3)
	for _, r := range results {
		if r.Threshold != 2 || r.Total != 3 {
			t.Fatalf("wrong metadata on participant %d", r.ParticipantID)
		}
	}
}
