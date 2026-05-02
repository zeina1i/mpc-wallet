package dkg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/zeina1i/mpc-wallet/pkg/pedersen"
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
	"github.com/zeina1i/mpc-wallet/pkg/vss"
)

var (
	ErrBroadcastMissing = errors.New("broadcast missing from participant")
	ErrInvalidShare     = errors.New("share failed VSS verification")
)

// Participant represents a DKG participant
type Participant interface {
	GetID() ParticipantID
	GetThreshold() int
	GetTotal() int

	// Round1 creates VSS shares.
	// Returns: broadcast data (public), and private shares keyed by recipient ID.
	Round1() (*Round1Broadcast, map[ParticipantID]*Round1Share, error)

	// ProcessBroadcast stores the public commitments from another participant.
	ProcessBroadcast(broadcast *Round1Broadcast) error

	// ProcessShare verifies and stores the private share from another participant.
	ProcessShare(share *Round1Share) error

	// Round2 combines all received shares into the final DKG output.
	Round2() (*DKGResult, error)
}

type ParticipantImpl struct {
	id         ParticipantID
	threshold  int
	total      int
	dealer     *vss.Dealer
	broadcast  *Round1Broadcast                   // own broadcast, set in Round1
	broadcasts map[ParticipantID]*Round1Broadcast // received from others
	shares     map[ParticipantID]*Round1Share     // received from others
}

// NewParticipant creates a new DKG participant with a freshly generated secret.
// seed is used to derive the shared Pedersen H parameter — all participants must use the same seed.
func NewParticipant(
	id ParticipantID,
	threshold, total int,
	seed []byte,
) (*ParticipantImpl, error) {
	N := shamir.Secp256k1Order()
	secret, err := rand.Int(rand.Reader, N)
	if err != nil {
		return nil, err
	}

	dealer, err := vss.NewDealer(secret, threshold, total, seed)
	if err != nil {
		return nil, err
	}

	broadcast := &Round1Broadcast{
		SenderID:    id,
		Commitments: dealer.Commitments(),
	}

	return &ParticipantImpl{
		dealer:     &dealer,
		id:         id,
		threshold:  threshold,
		total:      total,
		broadcast:  broadcast,
		broadcasts: make(map[ParticipantID]*Round1Broadcast),
		shares:     make(map[ParticipantID]*Round1Share),
	}, nil
}

func (p *ParticipantImpl) GetID() ParticipantID { return p.id }
func (p *ParticipantImpl) GetThreshold() int    { return p.threshold }
func (p *ParticipantImpl) GetTotal() int        { return p.total }

// Round1 packages the dealer's outputs for distribution.
// The broadcast (commitments) goes to everyone; each share goes privately to its recipient.
func (p *ParticipantImpl) Round1() (*Round1Broadcast, map[ParticipantID]*Round1Share, error) {
	fShares := p.dealer.Shares()
	gShares := p.dealer.BlindingShares()

	shares := make(map[ParticipantID]*Round1Share, p.total)
	for i := 0; i < p.total; i++ {
		recipientID := ParticipantID(i + 1)
		shares[recipientID] = &Round1Share{
			SenderID:   p.id,
			ReceiverID: recipientID,
			Share:      fShares[i],
			Blinding:   gShares[i],
		}
	}

	return p.broadcast, shares, nil
}

// ProcessBroadcast stores the public commitments from another participant.
func (p *ParticipantImpl) ProcessBroadcast(broadcast *Round1Broadcast) error {
	p.broadcasts[broadcast.SenderID] = broadcast
	return nil
}

// ProcessShare verifies the received share against the sender's published commitments,
// then stores it. Returns ErrInvalidShare if verification fails.
func (p *ParticipantImpl) ProcessShare(share *Round1Share) error {
	broadcast, ok := p.broadcasts[share.SenderID]
	if !ok {
		return fmt.Errorf("%w: from participant %d", ErrBroadcastMissing, share.SenderID)
	}

	params := p.dealer.Params()
	valid := vss.VerifyShare(
		params,
		share.Share.Value,
		share.Blinding.Value,
		int(p.id), // index is our own ID
		broadcast.Commitments,
	)
	if !valid {
		return fmt.Errorf("%w: from participant %d", ErrInvalidShare, share.SenderID)
	}

	p.shares[share.SenderID] = share
	return nil
}

// Round2 sums all received f-shares (including own) to produce the final secret share,
// and sums all C_k0 commitments to produce the group public key.
func (p *ParticipantImpl) Round2() (*DKGResult, error) {
	N := shamir.Secp256k1Order()

	// Collect all f-shares: own share + received shares
	// Own share is at index p.id - 1 (0-based)
	ownShare := p.dealer.Shares()[int(p.id)-1]

	sum := new(big.Int).Set(ownShare.Value)
	for _, s := range p.shares {
		sum.Add(sum, s.Share.Value)
		sum.Mod(sum, N)
	}

	finalShare := &shamir.Share{
		Index: int(p.id),
		Value: sum,
	}

	// Group public key Y = Σ C_k0 (sum of constant-term commitments from all participants)
	groupKey, err := p.computeGroupPublicKey()
	if err != nil {
		return nil, err
	}

	return &DKGResult{
		ParticipantID:  p.id,
		FinalShare:     finalShare,
		GroupPublicKey: groupKey,
		Threshold:      p.threshold,
		Total:          p.total,
	}, nil
}

// computeGroupPublicKey sums all participants' C_k0 (the commitment to the constant term).
// Y = Σ_k C_k0 = Σ_k (s_k * G + r_k * H)
// This equals (Σ s_k) * G + (Σ r_k) * H — the commitment to the combined secret.
func (p *ParticipantImpl) computeGroupPublicKey() (*pedersen.Point, error) {
	curve := btcec.S256()

	// Start with own commitment
	ownC0 := p.broadcast.Commitments[0]
	sumX := new(big.Int).Set(ownC0.Point.X)
	sumY := new(big.Int).Set(ownC0.Point.Y)

	for _, bc := range p.broadcasts {
		if len(bc.Commitments) == 0 {
			return nil, fmt.Errorf("%w: participant %d has no commitments", ErrBroadcastMissing, bc.SenderID)
		}
		c0 := bc.Commitments[0]
		sumX, sumY = curve.Add(sumX, sumY, c0.Point.X, c0.Point.Y)
	}

	return &pedersen.Point{X: sumX, Y: sumY}, nil
}
