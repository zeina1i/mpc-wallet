package dkg

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

// NewParticipant creates a new DKG participant
// params: VSS parameters
// id: this participant's ID (1, 2, 3, ...)
// threshold: minimum shares needed (t)
// total: total participants (n)
//func NewParticipant(
//	params *pedersen.Params,
//	id ParticipantID,
//	threshold, total int,
//) (Participant, error)
