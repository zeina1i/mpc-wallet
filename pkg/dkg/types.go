package dkg

import (
	"github.com/zeina1i/mpc-wallet/pkg/pedersen"
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
)

// ParticipantID identifies a participant
type ParticipantID int

// Round1Broadcast contains public data broadcast in round 1
type Round1Broadcast struct {
	SenderID    ParticipantID
	Commitments []*pedersen.Commitment
}

// Round1Share contains private share for specific participant
type Round1Share struct {
	SenderID   ParticipantID
	ReceiverID ParticipantID
	Share      *shamir.Share
}

// DKGResult is the final output
type DKGResult struct {
	ParticipantID ParticipantID
	FinalShare    *shamir.Share
	Threshold     int
	Total         int
}
