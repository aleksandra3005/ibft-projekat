package consensus

import (
	"fmt"
	"time"
)

type IBFTNode struct {
	ID         int
	Lambda     int
	Round      int
	PR         int
	PV         string
	InputValue string

	// Kanali za komunikaciju
	MsgChan   chan IBFTMessage         // Moj sandučić za poruke
	PeerChans map[int]chan IBFTMessage // Adrese ostalih čvorova

	PrepareVotes map[string]map[int]bool // Value -> SenderID -> true
	CommitVotes  map[string]map[int]bool // Value -> SenderID -> true
	Validators   []int
	Decided      bool

	Timer               *time.Timer
	IsOffline           bool
	SimulateInsertError bool // Da li simuliramo grešku pri upisu u bazu?
	Scenario7R1Fail     bool // Specifično za scenario 7
	Scenario4Fail       bool

	// RoundChangeMessages čuva primljene RC poruke za trenutnu rundu
	// Mapa: Round -> SenderID -> Poruka
	RCStore map[int]map[int]IBFTMessage // Round -> SenderID -> Message

	LastStartedRound int // Dodaj ovo da pratimo koju smo rundu zadnju pokrenuli
}

func NewIBFTNode(id int, input string, allValidators []int) *IBFTNode {
	return &IBFTNode{
		ID:                  id,
		Lambda:              1,
		Round:               1,
		PR:                  -1,
		PV:                  "",
		InputValue:          input,
		MsgChan:             make(chan IBFTMessage, 100), // Kapacitet sandučića 100 poruka
		PeerChans:           make(map[int]chan IBFTMessage),
		PrepareVotes:        make(map[string]map[int]bool),
		CommitVotes:         make(map[string]map[int]bool),
		Validators:          allValidators,
		SimulateInsertError: false, // Inicijalno je isključeno

		Timer: time.NewTimer(5 * time.Second), // Inicijalno ga podesimo na 5 sekundi

		RCStore:          make(map[int]map[int]IBFTMessage),
		LastStartedRound: 0,
	}
}

// Broadcast salje poruku svim validatorima (ukljucujuci i sebe)
func (n *IBFTNode) Broadcast(msg IBFTMessage) {
	for _, peerChan := range n.PeerChans {
		peerChan <- msg
	}
}

// HandleMessage je mozak algoritma (Algorithm 2 i 3 iz rada)
func (n *IBFTNode) HandleMessage(msg IBFTMessage) {
	if n.IsOffline {
		return
	} // Ako je mrtav, ne prima poruke

	switch msg.Type {
	case PrePrepare:
		// Ako smo već u ovoj rundi poslali Prepare, ignorišemo dupli Pre-Prepare
		if n.PR == n.Round {
			return
		}

		// Algoritam 4: JustifyPrePrepare
		// Ako nismo u Rundi 1, a lider šalje nešto što nije "HighestPrepared", odbijamo
		if msg.Round > 1 {
			n.Log(">>> ANALIZA DOKAZA (ProofRC): %s", n.FormatProof(msg.ProofRC))

			if len(msg.ProofRC) < n.Quorum() {
				n.Log("ALARM: Lider poslao PRE-PREPARE bez kvoruma u dokaza!")
				return
			}

			// NOVA KLJUČNA PROVERA: Da li je vrednost opravdana?
			opravdanaVrednost := n.GetValueFromProof(msg.ProofRC)
			if msg.Value != opravdanaVrednost {
				n.Log("!!! KRŠENJE BEZBEDNOSTI !!! Lider predlaze %s, a dokaz kaze da mora %s. ODBIJAM!", msg.Value, opravdanaVrednost)
				return // Čvor prestaje da obrađuje ovu poruku i ne šalje PREPARE
			}

			// Ovde bi se u pravoj mreži proveravalo i da li su potpisi validni
			n.Log("Dokaz (ProofRC) je validan. Prihvatam predlog novog lidera.")
		}

		n.Timer.Reset(n.GetTimerDuration())
		n.Log("Primio PRE-PREPARE od Node %d za vrednost: %s. Saljem PREPARE...", msg.SenderID, msg.Value)

		// Čuvamo šta smo videli u ovoj rundi da bismo znali da pošaljemo u ROUND-CHANGE ako tajmer istekne
		//n.PR = msg.Round
		//n.PV = msg.Value

		prepareMsg := IBFTMessage{
			Type: Prepare, Lambda: n.Lambda, Round: n.Round, Value: msg.Value, SenderID: n.ID,
		}
		n.Broadcast(prepareMsg)

	case Prepare:
		if n.Decided {
			return
		} // Ako je blok gotov, ne gledaj više Prepare

		// 2. Brojimo glasove za PREPARE
		if n.PrepareVotes[msg.Value] == nil {
			n.PrepareVotes[msg.Value] = make(map[int]bool)
		}

		// Provera: Da li smo za ovu rundu VEĆ poslali COMMIT?
		// Koristimo PR (Prepared Round) da znamo da smo već zaključali ovaj nivo
		if n.PR == n.Round {
			return
		}

		// Zabeleži glas (ako Node 2 pošalje 10 poruka, ovde će se samo prepisati "true")
		n.PrepareVotes[msg.Value][msg.SenderID] = true

		count := len(n.PrepareVotes[msg.Value]) // len() sad vraća broj UNIKATNIH glasova

		// Loguj samo dok ne stignemo do kvoruma, da ne gledamo 4/3
		if count <= n.Quorum() {
			n.Log("Primio PREPARE od Node %d za [%s] (Ukupno: %d/%d)", msg.SenderID, msg.Value, count, n.Quorum())
		}

		// 3. Ako imamo kvorum (3 od 4), saljemo COMMIT
		// f=1, n=4 => kvorum je 2f+1 = 3
		if count >= n.Quorum() {
			// SADA ažuriramo memoriju (zaključavamo vrednost)
			n.PR = n.Round
			n.PV = msg.Value
			n.Log("--- ZAKLJUČAO SAM vrednost %s za rundu %d ---", n.PV, n.PR)

			// --- NOVA LOGIKA ZA SCENARIO 4 ---
			if n.Scenario4Fail && (n.ID == 0 || n.ID == 3) {
				n.Log("!!! SCENARIO 4 !!! Čvor se gasi NAKON zaključavanja, a pre slanja COMMIT-a.")
				n.Stop()
				return // Prekidamo ovde, čvor nikada neće poslati COMMIT
			}

			// --- KLJUČNA KOČNICA ZA SCENARIO 7 ---
			if n.Scenario7R1Fail && n.Round == 1 {
				n.Log("!!! SCENARIO 7 !!! Čvor se gasi NAKON zaključavanja, a PRE slanja COMMIT-a.")
				n.Stop()
				return // Ovde prekidamo, nema slanja COMMIT-a!
			}

			n.Log("Kvorum postignut za PREPARE! Saljem COMMIT...")
			commitMsg := IBFTMessage{
				Type:     Commit,
				Lambda:   n.Lambda,
				Round:    n.Round,
				Value:    msg.Value,
				SenderID: n.ID,
			}
			n.Broadcast(commitMsg)
		}

	case Commit:
		if n.Decided {
			return
		} // KLJUČNA KOČNICA: Ignoriši sve ako je konsenzus već pao

		// BROJIMO GLASOVE ZA COMMIT (ovde si imala PrepareVotes grešku)
		if n.CommitVotes[msg.Value] == nil {
			n.CommitVotes[msg.Value] = make(map[int]bool)
		}

		// Zabeleži glas u CommitVotes mapu
		n.CommitVotes[msg.Value][msg.SenderID] = true

		count := len(n.CommitVotes[msg.Value])

		// Logujemo samo do 3/3
		if count <= n.Quorum() {
			n.Log("Primio COMMIT od Node %d (Napredak: %d/%d)", msg.SenderID, count, n.Quorum())
		}

		if count >= n.Quorum() {
			// SCENARIO 5: Simuliramo da upis u bazu ne uspe
			if n.SimulateInsertError {
				n.Log("!!! GRESKA PRI UPISU U BAZU !!! Ne mogu da finalizujem blok.")
				return
			}

			n.Decided = true
			n.Log("--- !!! KONSENZUS POSTIGNUT !!! ---")
			n.Log("Blok %d je uspesno potvrdjen sa vrednoscu: %s", n.Lambda, msg.Value)

			// NOVO: Prelazak na sledeći blok nakon 2 sekunde pauze
			go func() {
				time.Sleep(4 * time.Second)
				n.NextInstance()
			}()
		}

	case RoundChange:
		// Prvo inicijalizujemo mapu za tu rundu ako ne postoji
		if n.RCStore[msg.Round] == nil {
			n.RCStore[msg.Round] = make(map[int]IBFTMessage)
		}
		// Sačuvamo poruku
		n.RCStore[msg.Round][msg.SenderID] = msg

		// Ako vidimo f+1 (to je 2 čvora) da su u VIŠOJ rundi od nas, moramo i mi tamo
		if msg.Round > n.Round && len(n.RCStore[msg.Round]) >= n.FPlusOne() {
			n.Log("Vidim f+1 ROUND-CHANGE poruka za rundu %d. Pridruzujem se!", msg.Round)
			n.OnTimerExpire()
			return
		}

		count := len(n.RCStore[n.Round])

		// Ako smo lider i imamo kvorum (3 poruke)
		// stavila sam == da mi se ne ispisuje sve dvaput
		if n.IsLeader() && count >= n.Quorum() && n.LastStartedRound < n.Round && !n.Decided {
			n.LastStartedRound = n.Round // ZAKLJUČAVAMO: da ne bismo ponovo ušli ovde za istu rundu
			// Koristimo novu funkciju da dobijemo i dokaz (ProofRC) i vrednost
			dokaz, vrednost := n.GetRCProof()

			n.Log("Analizom dokaza (ProofRC) vidim da je opravdana vrednost: %s", vrednost)

			// DODAJ OVAJ MALI "HACK" SAMO ZA DEMONSTRACIJU:
			// Ako smo u Rundi 2 i Scenario je 7, nateraj lidera da predloži "ZLONAMERNA_VREDNOST"
			// (Ovo mozes i rucno da objasnis profesoru da si uradila da testiras Justify)
			if n.Round == 2 && n.ID == 2 {
				n.Log("ZLONAMERNI MOD: Ignorišem dokaz i pokušavam da podmetnem ZLONAMERNA_VREDNOST!")
				vrednost = "ZLONAMERNA_VREDNOST"
			}

			n.Start(n.Lambda, n.Round, vrednost, dokaz)
		}
	}
}

func (n *IBFTNode) IsLeader() bool {
	// Lider je cvor ciji ID odgovara trenutnoj rundi (npr. R1 -> Node 1, R2 -> Node 2...)
	// Koristimo modulo da bi se vrtelo u krug (0, 1, 2, 3, 0...)
	return n.ID == ((n.Lambda + n.Round) % len(n.Validators))
}

func (n *IBFTNode) Start(lambda int, round int, value string, proof []IBFTMessage) {
	n.Lambda = lambda
	n.Round = round // <-- Sada koristimo prosleđenu rundu, ne kucamo 1!
	// IZMENI OVO: Postavi InputValue samo ako je runda 1
	// Ako je runda > 1, koristi ono što je lider (ili hack) poslao
	if n.Round == 1 {
		n.InputValue = fmt.Sprintf("VREDNOST_ZA_BLOK_%d", lambda)
	}

	n.Timer.Reset(n.GetTimerDuration())

	if n.IsLeader() {
		// VREDNOST KOJU ŠALJEMO:
		// Ako je prosleđena vrednost drugačija (npr. naš hack), šaljemo nju,
		// inače šaljemo naš InputValue.
		proposeValue := n.InputValue
		if value != "" && value != n.InputValue {
			proposeValue = value
			n.Log("!!! PAŽNJA !!! Kao lider pokušavam da nametnem vrednost: %s (umesto originalne: %s)", proposeValue, n.InputValue)
		} else {
			n.Log("Ja sam LIDER. Predlažem legitimnu vrednost: %s", proposeValue)
		}

		msg := IBFTMessage{
			Type:     PrePrepare,
			Lambda:   n.Lambda,
			Round:    n.Round,
			Value:    proposeValue,
			SenderID: n.ID,
			ProofRC:  proof, // Ubacujemo dokaz u poruku
		}
		n.Broadcast(msg)
	} else {
		aktuelniLider := (n.Lambda + n.Round) % len(n.Validators)
		n.Log("Ja sam validator. Lider za ovu rundu je Node %d. Cekam poruku...", aktuelniLider)
	}
}

func (n *IBFTNode) Log(format string, args ...interface{}) {
	prefix := fmt.Sprintf("[Node %d][Round %d] ", n.ID, n.Round)
	fmt.Printf(prefix+format+"\n", args...)
}

func (n *IBFTNode) GetTimerDuration() time.Duration {
	// 5 sekundi * (2 na nivo runde) -> 5s, 10s, 20s...
	return time.Duration(5*(1<<(n.Round-1))) * time.Second
}

func (n *IBFTNode) OnTimerExpire() {
	if n.IsOffline || n.Decided {
		return
	}

	n.Round++
	n.Log("TAJMER ISTEKAO! Prelazim na Rundu %d. Saljem ROUND-CHANGE...", n.Round)

	n.PrepareVotes = make(map[string]map[int]bool)
	n.CommitVotes = make(map[string]map[int]bool)

	msg := IBFTMessage{
		Type:          RoundChange,
		Lambda:        n.Lambda,
		Round:         n.Round,
		SenderID:      n.ID,
		PreparedRound: n.PR, // Šaljemo šta smo zadnje "pripremili"
		PreparedValue: n.PV,
	}
	n.Broadcast(msg)
	n.Timer.Reset(n.GetTimerDuration())
}

func (n *IBFTNode) Stop() {
	n.IsOffline = true
	n.Log("--- ČVOR SE UGASIO (CRASH) ---")
}

// HighestPrepared
func (n *IBFTNode) SelectValueFromRC() string {
	highestPR := -1
	highestPV := n.InputValue // Default ako niko ništa nije pripremio

	msgs, postojanje := n.RCStore[n.Round]
	if !postojanje {
		return highestPV
	}

	for _, msg := range msgs {
		if msg.PreparedRound > highestPR && msg.PreparedValue != "" {
			highestPR = msg.PreparedRound
			highestPV = msg.PreparedValue
		}
	}
	return highestPV
}

// Quorum računa potreban broj glasova za odluku (2f + 1)
func (n *IBFTNode) Quorum() int {
	totalNodes := len(n.Validators)
	f := (totalNodes - 1) / 3
	return 2*f + 1
}

// FPlusOne računa f + 1 (signal da je bar jedan pošten čvor video problem)
func (n *IBFTNode) FPlusOne() int {
	f := (len(n.Validators) - 1) / 3
	return f + 1
}

func (n *IBFTNode) Run() {
	n.Log("Pokrenut i ceka poruke ili tajmer...")
	for {
		select {
		case msg := <-n.MsgChan:
			if !n.IsOffline { // Čvor obrađuje poruke samo ako NIJE offline
				n.HandleMessage(msg)
			}
		case <-n.Timer.C:
			if !n.IsOffline { // Čvor reaguje na tajmer samo ako NIJE offline
				n.OnTimerExpire()
			}
		default:
			time.Sleep(10 * time.Millisecond) // Da ne opterecuje procesor dok ceka
		}
	}
}

func (n *IBFTNode) NextInstance() {
	if n.IsOffline {
		return
	} // Ako je čvor ugašen, ne radi ništa i ne piši logove

	n.Lambda++
	n.Round = 1
	n.PR = -1
	n.PV = ""
	n.Decided = false
	n.PrepareVotes = make(map[string]map[int]bool)
	n.CommitVotes = make(map[string]map[int]bool)
	n.RCStore = make(map[int]map[int]IBFTMessage)

	// Simuliramo da lider uzima nove podatke za novi blok
	// npr. dodamo broj bloka u naziv vrednosti
	n.InputValue = fmt.Sprintf("VREDNOST_ZA_BLOK_%d", n.Lambda)

	n.Log(">>> PRELAZIM NA SLEDECI BLOK: Lambda %d <<<", n.Lambda)
	n.Start(n.Lambda, 1, n.InputValue, nil)
}

func (n *IBFTNode) GetRCProof() ([]IBFTMessage, string) {
	msgs := n.RCStore[n.Round]
	var proof []IBFTMessage
	highestPR := -1
	highestPV := n.InputValue

	for _, m := range msgs {
		proof = append(proof, m)
		if m.PreparedRound > highestPR && m.PreparedValue != "" {
			highestPR = m.PreparedRound
			highestPV = m.PreparedValue
		}
	}
	return proof, highestPV
}

// GetValueFromProof izvlači opravdanu vrednost iz liste ProofRC poruka
func (n *IBFTNode) GetValueFromProof(proof []IBFTMessage) string {
	highestPR := -1
	highestPV := n.InputValue // Ako niko ništa nije pripremio, liderova vrednost je OK

	for _, m := range proof {
		if m.PreparedRound > highestPR && m.PreparedValue != "" {
			highestPR = m.PreparedRound
			highestPV = m.PreparedValue
		}
	}
	return highestPV
}

// Pomoćna funkcija za lep ispis dokaza
func (n *IBFTNode) FormatProof(proof []IBFTMessage) string {
	if len(proof) == 0 {
		return "[]"
	}
	res := "["
	for _, m := range proof {
		pvPrikaz := m.PreparedValue
		if pvPrikaz == "" {
			pvPrikaz = "⊥" // Simbol za prazno (bottom)
		}
		res += fmt.Sprintf("{V%d: PR=%d, PV=%s} ", m.SenderID, m.PreparedRound, pvPrikaz)
	}
	res += "]"
	return res
}
