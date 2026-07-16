package consensus

// Tipovi poruka
const (
	PrePrepare  = "PRE-PREPARE"
	Prepare     = "PREPARE"
	Commit      = "COMMIT"
	RoundChange = "ROUND-CHANGE"
)

// IBFTMessage je struktura za svaku poruku u mreži
type IBFTMessage struct {
	Type     string // PrePrepare, Prepare, itd.
	Lambda   int    // Visina bloka (Sequence)
	Round    int    // Runda (ri)
	Value    string // Vrednost (predlog bloka)
	SenderID int    // ID validatora koji šalje poruku

	Signature []byte // "digitalni pečat" koji dokazuje ko je poslao poruku i da ona nije menjana

	// Polja za Round-Change
	PreparedRound int
	PreparedValue string

	// Dokaz o promeni runde (skup RC poruka koje je lider prikupio)
	ProofRC []IBFTMessage
}
