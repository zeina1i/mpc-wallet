package dkg

import (
	"crypto/rand"
	"github.com/zeina1i/mpc-wallet/pkg/pedersen"
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
	"github.com/zeina1i/mpc-wallet/pkg/vss"
)

// Participant represents a DKG participant
type Participant interface {
	// GetID returns participant's ID
	GetID() ParticipantID

	// Round1 creates VSS shares
	// Returns: broadcast data, shares for each participant
	Round1() (*Round1Broadcast, map[ParticipantID]*Round1Share, error)

	// ProcessBroadcast processes public broadcast from another participant
	ProcessBroadcast(broadcast *Round1Broadcast) error

	// ProcessShare processes private share from another participant
	ProcessShare(share *Round1Share) error

	// Round2 combines all received shares
	// Returns: final combined share and public key
	Round2() (*DKGResult, error)

	// GetThreshold returns threshold value
	GetThreshold() int

	// GetTotal returns total participants
	GetTotal() int
}

type ParticipantImpl struct {
	id         ParticipantID
	threshold  int
	total      int
	dealer     *vss.Dealer                        // created in Round1
	broadcast  *Round1Broadcast                   // your own broadcast, set in Round1
	broadcasts map[ParticipantID]*Round1Broadcast // received from others
	shares     map[ParticipantID]*Round1Share     // received from others    }
}

// NewParticipant creates a new DKG participant
// params: VSS parameters
// id: this participant's ID (1, 2, 3, ...)
// threshold: minimum shares needed (t)
// total: total participants (n)
func NewParticipant(
	params *pedersen.Params,
	id ParticipantID,
	threshold, total int,
) (*ParticipantImpl, error) {
	N := shamir.Secp256k1Order()
	secret, err := rand.Int(rand.Reader, N)
	if err != nil {
		return nil, err
	}

	dealer, err := vss.NewDealer(secret, threshold, total, []byte("main-seed"))
	if err != nil {
		return nil, err
	}

	broadcast := &Round1Broadcast{
		SenderID:    id,
		Commitments: dealer.Commitments(),
	}

	return &ParticipantImpl{
		dealer:    &dealer,
		id:        id,
		threshold: threshold,
		total:     total,
		broadcast: broadcast,
	}, nil
}
