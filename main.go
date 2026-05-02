package main

import (
	"fmt"
	"log"

	"github.com/zeina1i/mpc-wallet/pkg/dkg"
)

func main() {
	seed := []byte("shared-pedersen-seed")
	threshold := 2
	total := 3

	fmt.Printf("=== DKG: %d-of-%d ===\n\n", threshold, total)

	// Create participants
	participants := make([]*dkg.ParticipantImpl, total)
	for i := 0; i < total; i++ {
		p, err := dkg.NewParticipant(dkg.ParticipantID(i+1), threshold, total, seed)
		if err != nil {
			log.Fatalf("failed to create participant %d: %v", i+1, err)
		}
		participants[i] = p
	}

	// Round 1: generate and distribute broadcasts + shares
	broadcasts := make([]*dkg.Round1Broadcast, total)
	allShares := make([]map[dkg.ParticipantID]*dkg.Round1Share, total)
	for i, p := range participants {
		bc, shares, err := p.Round1()
		if err != nil {
			log.Fatalf("participant %d Round1: %v", i+1, err)
		}
		broadcasts[i] = bc
		allShares[i] = shares
		fmt.Printf("Participant %d: generated %d commitments\n", i+1, len(bc.Commitments))
	}

	// Distribute broadcasts and shares to every other participant
	for _, p := range participants {
		for _, bc := range broadcasts {
			if bc.SenderID == p.GetID() {
				continue
			}
			if err := p.ProcessBroadcast(bc); err != nil {
				log.Fatalf("participant %d ProcessBroadcast: %v", p.GetID(), err)
			}
		}
		for senderIdx, shares := range allShares {
			senderID := dkg.ParticipantID(senderIdx + 1)
			if senderID == p.GetID() {
				continue
			}
			if err := p.ProcessShare(shares[p.GetID()]); err != nil {
				log.Fatalf("participant %d ProcessShare from %d: %v", p.GetID(), senderID, err)
			}
		}
	}

	// Round 2: combine shares
	fmt.Println()
	var groupKey string
	for _, p := range participants {
		res, err := p.Round2()
		if err != nil {
			log.Fatalf("participant %d Round2: %v", p.GetID(), err)
		}
		if groupKey == "" {
			groupKey = res.GroupPublicKey.X.String()[:16] + "..."
		}
		fmt.Printf("Participant %d: final share index=%d value=%s...\n",
			res.ParticipantID, res.FinalShare.Index, res.FinalShare.Value.String()[:16])
	}

	fmt.Printf("\nGroup public key X: %s\n", groupKey)
	fmt.Println("DKG complete.")
}
