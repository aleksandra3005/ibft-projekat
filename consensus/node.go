package consensus

// Uvozimo standardne biblioteke za formatiranje teksta (fmt) i rad sa vremenom (time)
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"

	"fmt"
	"time"
)

// Ova struktura predstavlja jedan server (čvor) u mreži
type IBFTNode struct {
	ID         int
	Lambda     int
	Round      int
	PR         int
	PV         string
	InputValue string

	// Kanali za komunikaciju
	MsgChan   chan IBFTMessage         // Moj sandučić za poruke
	PeerChans map[int]chan IBFTMessage // Adrese ostalih čvorova (Mapa gde su ključevi ID-jevi drugih čvorova, a vrednosti njihovi kanali. Preko ovoga šaljemo poruke drugima.)

	PrepareVotes map[string]map[int]bool // Prati ko je poslao PREPARE poruku. Struktura je: Value -> SenderID -> true
	CommitVotes  map[string]map[int]bool // Value -> SenderID -> true
	Validators   []int                   // Lista ID-jeva svih čvorova koji učestvuju u glasanju
	Decided      bool                    // Flag koja postaje true kada čvor definitivno postigne dogovor

	Timer               *time.Timer
	IsOffline           bool // Ako je true, čvor se ponaša kao da je ugašen
	SimulateInsertError bool // Simulira grešku prilikom upisa u bazu
	Scenario7R1Fail     bool // Specifično za scenario 7
	Scenario4Fail       bool // Specifično za scenario 4

	// RoundChangeMessages čuva primljene RC poruke za trenutnu rundu - Pamti ko je tražio prelazak u koju rundu
	// Mapa: Round -> SenderID -> Poruka
	RCStore map[int]map[int]IBFTMessage // Round -> SenderID -> Message

	LastStartedRound int // Pomoćna promenljiva da čvor ne bi više puta pokretao istu rundu

	// Kriptografski ključevi
	PrivateKey     *ecdsa.PrivateKey        // Privatni ključ za potpisivanje
	PeerPublicKeys map[int]*ecdsa.PublicKey // Javni ključevi svih ostalih validatora
}

// Ova funkcija (konstruktor) pravi novu instancu čvora
func NewIBFTNode(id int, input string, allValidators []int) *IBFTNode {
	n := &IBFTNode{
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
		PeerPublicKeys:   make(map[int]*ecdsa.PublicKey),
	}

	// Generisanje ključeva - Svaki put kad napravimo čvor, on dobije jedinstven identitet
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	n.PrivateKey = privKey
	return n
}

// Pomoćna funkcija koja potpisuje poruku
func (n *IBFTNode) SignMessage(msg *IBFTMessage) {
	msg.Signature = nil // Očistimo potpis pre nego što napravimo hash podataka
	data, _ := json.Marshal(msg)
	hash := sha256.Sum256(data) // hash (digitalni otisak)
	// Privatnim ključem se taj hash "zaključa" u digitalni potpis i ubaci nazad u poruku
	sig, _ := ecdsa.SignASN1(rand.Reader, n.PrivateKey, hash[:])
	msg.Signature = sig
}

// Broadcast salje poruku svim validatorima (ukljucujuci i sebe)
func (n *IBFTNode) Broadcast(msg IBFTMessage) {
	// Potpisivanje poruke pre slanja

	n.SignMessage(&msg) // Potpisujemo poruku pre nego što ode na mrežu                                         // 4. Ubacimo potpis u poruku

	// Prolazi kroz mapu kanala svih ostalih čvorova
	for _, peerChan := range n.PeerChans {
		peerChan <- msg // Ubacuje poruku u kanal svakog čvora (šalje im poruku)
	}
}

// HandleMessage je mozak algoritma (Algorithm 2 i 3 iz rada)
func (n *IBFTNode) HandleMessage(msg IBFTMessage) {
	if n.IsOffline {
		return
	} // Ako je mrtav, ne prima poruke

	// Verifikacija potpisa
	// Čvor traži javni ključ pošiljaoca u svojoj mapi. Ako ga nema, poruka je od nepoznate osobe i odmah se odbacuje
	pubKey, ok := n.PeerPublicKeys[msg.SenderID]
	if !ok || pubKey == nil {
		n.Log("UPOZORENJE: Nemam javni kljuc za Node %d, odbacujem poruku.", msg.SenderID)
		return
	}

	sig := msg.Signature
	msg.Signature = nil // Privremeno sklanjamo potpis radi provere hasha
	data, _ := json.Marshal(msg)
	hash := sha256.Sum256(data)

	// Ako se hash koji je čvor izračunao poklapa sa onim što je unutar potpisa (otključano javnim ključem pošiljaoca), poruka je validna
	if !ecdsa.VerifyASN1(pubKey, hash[:], sig) {
		n.Log("ALARM: Nevalidan potpis od Node %d!", msg.SenderID)
		return
	}
	msg.Signature = sig // Vraćamo potpis nazad u poruku nakon provere

	switch msg.Type { // Razvrstava poruke na tipove: PrePrepare, Prepare, Commit, i RoundChange
	case PrePrepare:
		if msg.Round != n.Round {
			return
		} // Ignoriši ako runda nije ista

		// Ako smo već u ovoj rundi poslali Prepare, ignorišemo dupli Pre-Prepare
		if n.PR == n.Round {
			return
		}

		// Algoritam 4: JustifyPrePrepare
		// Ako nismo u Rundi 1, a lider šalje nešto što nije HighestPrepared, odbijamo
		if msg.Round > 1 {
			n.Log(">>> ANALIZA DOKAZA (ProofRC): %s", n.FormatProof(msg.ProofRC))

			// msg.ProofRC: Sadrži dokaze (RoundChange poruke) od drugih čvorova
			if len(msg.ProofRC) < n.Quorum() {
				n.Log("ALARM: Lider poslao PRE-PREPARE bez kvoruma u dokaza!")
				return
			}

			// PROVERA: Da li je vrednost opravdana?
			// n.GetValueFromProof(msg.ProofRC) izvlači vrednost koja je zaključana u prethodnim rundama
			opravdanaVrednost := n.GetValueFromProof(msg.ProofRC)
			if msg.Value != opravdanaVrednost {
				n.Log("!!! KRŠENJE BEZBEDNOSTI !!! Lider predlaze %s, a dokaz kaze da mora %s. ODBIJAM!", msg.Value, opravdanaVrednost)
				return // Čvor prestaje da obrađuje ovu poruku i ne šalje PREPARE
			}

			n.Log("Dokaz (ProofRC) je validan. Prihvatam predlog novog lidera.")
		}

		// Ako je sve u redu, čvor resetuje tajmer (jer lider radi svoj posao) i šalje Prepare poruku svima
		n.Timer.Reset(n.GetTimerDuration())
		n.Log("Primio PRE-PREPARE od Node %d za vrednost: %s. Saljem PREPARE...", msg.SenderID, msg.Value)

		prepareMsg := IBFTMessage{
			Type: Prepare, Lambda: n.Lambda, Round: n.Round, Value: msg.Value, SenderID: n.ID,
		}
		n.Broadcast(prepareMsg)

	case Prepare:
		if msg.Round != n.Round {
			return
		} // Ignoriši ako runda nije ista

		if n.Decided {
			return
		} // Ako je blok gotov, ne gledaj više Prepare

		// Brojimo glasove za PREPARE za vrednost koja je stigla u poruci
		if n.PrepareVotes[msg.Value] == nil {
			// Ako ta vrednost ne postoji, pravi novu mapu za tu vrednost gde će beležiti ID-jeve čvorova koji su glasali
			n.PrepareVotes[msg.Value] = make(map[int]bool)
		}

		// Koristimo PR (Prepared Round) da znamo da smo već zaključali ovaj nivo
		if n.PR == n.Round {
			return
		}

		// Zabeleži glas (ako Node 2 pošalje 10 poruka, ovde će se samo prepisati "true")
		n.PrepareVotes[msg.Value][msg.SenderID] = true

		count := len(n.PrepareVotes[msg.Value]) // len() sad vraća broj UNIKATNIH glasova

		// Loguj samo dok ne stignemo do kvoruma, da ne gledamo 4/3 (da ne zatrpavamo ekran)
		if count <= n.Quorum() {
			n.Log("Primio PREPARE od Node %d za [%s] (Ukupno: %d/%d)", msg.SenderID, msg.Value, count, n.Quorum())
		}

		// Ako imamo kvorum (3 od 4), saljemo COMMIT
		if count >= n.Quorum() {
			// ažuriramo memoriju (zaključavamo vrednost)
			n.PR = n.Round   // Čvor postavlja svoj Prepared Round na trenutnu rundu
			n.PV = msg.Value // Čvor "zaključava" vrednost (Prepared Value) – od sada pa nadalje u ovoj rundi on priznaje samo tu vrednost
			n.Log("--- ZAKLJUČAO SAM vrednost %s za rundu %d ---", n.PV, n.PR)

			// LOGIKA ZA SCENARIO 4
			if n.Scenario4Fail && (n.ID == 0 || n.ID == 3) {
				n.Log("!!! SCENARIO 4 !!! Čvor se gasi NAKON zaključavanja, a pre slanja COMMIT-a.")
				n.Stop()
				return // Prekidamo ovde, čvor nikada neće poslati COMMIT
			}

			// LOGIKA ZA SCENARIO 7
			if n.Scenario7R1Fail && n.Round == 1 {
				n.Log("!!! SCENARIO 7 !!! Čvor se gasi NAKON zaključavanja, a PRE slanja COMMIT-a.")
				n.Stop()
				return // Ovde prekidamo, nema slanja COMMIT-a!
			}

			n.Log("Kvorum postignut za PREPARE! Saljem COMMIT...")
			// Kreira novu poruku tipa Commit sa trenutnom Lambdom, Rundom i vrednošću
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
		if msg.Round != n.Round {
			return
		}

		if n.Decided {
			return
		} // Ignoriši sve ako je konsenzus već postignut

		// BROJIMO GLASOVE ZA COMMIT
		if n.CommitVotes[msg.Value] == nil {
			n.CommitVotes[msg.Value] = make(map[int]bool)
		}

		// Zabeleži glas u CommitVotes mapu (Ako isti čvor pošalje više puta, mapa osigurava da se broji samo jednom)
		n.CommitVotes[msg.Value][msg.SenderID] = true

		count := len(n.CommitVotes[msg.Value]) // Računa ukupan broj unikatnih Commit glasova

		// Logujemo samo do 3/3
		if count <= n.Quorum() {
			n.Log("Primio COMMIT od Node %d (Napredak: %d/%d)", msg.SenderID, count, n.Quorum())
		}

		if count >= n.Quorum() {
			// SCENARIO 5: Simuliramo da upis u bazu ne uspe
			if n.SimulateInsertError {
				n.Log("!!! GRESKA PRI UPISU U BAZU !!! Ne mogu da finalizujem blok.")
				// n.Decided = true
				return
			}

			// KLJUČNI MOMENAT: Čvor zvanično označava da je za njega konsenzus postignut
			n.Decided = true
			n.Log("--- !!! KONSENZUS POSTIGNUT !!! ---")
			n.Log("Blok %d je uspesno potvrdjen sa vrednoscu: %s", n.Lambda, msg.Value)

			// Pokreće asinhronu funkciju (gorutinu) koja radi u pozadini kako ne bi blokirala glavni kod
			// Prelazak na sledeći blok nakon 4 sekunde pauze
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
		// Sačuvamo poruku u RCStore (skladište poruka za promenu runde)
		n.RCStore[msg.Round][msg.SenderID] = msg

		// Ako vidimo f+1 (to je 2 čvora) da su u VIŠOJ rundi od nas, moramo i mi tamo
		if msg.Round > n.Round && len(n.RCStore[msg.Round]) >= n.FPlusOne() {
			n.Log("Vidim f+1 ROUND-CHANGE poruka za rundu %d. Pridruzujem se!", msg.Round)
			n.OnTimerExpire() // Čvor veštački izaziva prekid trenutne runde i sam šalje zahtev za prelazak u tu višu rundu
			return
		}

		// Broji koliko je ukupno RoundChange poruka stiglo za trenutnu rundu u kojoj se čvor nalazi
		count := len(n.RCStore[n.Round])

		// Ako smo lider i imamo kvorum (3 poruke)
		if n.IsLeader() && count >= n.Quorum() && n.LastStartedRound < n.Round && !n.Decided {
			n.LastStartedRound = n.Round // ZAKLJUČAVAMO: da ne bismo ponovo ušli ovde za istu rundu
			// Koristimo novu funkciju da dobijemo i dokaz (ProofRC) i vrednost
			// Lider pregleda sve pristigle RoundChange poruke i traži "opravdanje" – koja je vrednost bila najbliža dogovoru u prethodnim pokušajima
			dokaz, vrednost := n.GetRCProof()

			n.Log("Analizom dokaza (ProofRC) vidim da je opravdana vrednost: %s", vrednost)

			// Ako smo u Rundi 2 i Scenario je 7, nateraj lidera da predloži ZLONAMERNA_VREDNOST
			if n.Round == 2 && n.ID == 2 {
				n.Log("ZLONAMERNI MOD: Ignorišem dokaz i pokušavam da podmetnem ZLONAMERNA_VREDNOST!")
				// Podmeće se netačna vrednost umesto one koju je dokaz (ProofRC) naložio
				vrednost = "ZLONAMERNA_VREDNOST"
			}

			// Lider zvanično započinje novu rundu slanjem PrePrepare poruke koja sadrži izabranu vrednost i prikupljene dokaze
			n.Start(n.Lambda, n.Round, vrednost, dokaz)
		}
	}
}

// funkcija koja proverava da li je trenutni čvor lider
func (n *IBFTNode) IsLeader() bool {
	return n.ID == ((n.Lambda + n.Round) % len(n.Validators))
}

func (n *IBFTNode) Start(lambda int, round int, value string, proof []IBFTMessage) {
	n.Lambda = lambda // Postavlja čvor na nivo bloka koji se trenutno obrađuje
	n.Round = round
	// Postavi InputValue samo ako je runda 1
	// Ako je runda > 1, koristi ono što je lider (ili hack) poslao
	if n.Round == 1 {
		n.InputValue = fmt.Sprintf("VREDNOST_ZA_BLOK_%d", lambda)
	}

	n.Timer.Reset(n.GetTimerDuration())

	if n.IsLeader() {
		// Ako je prosleđena vrednost drugačija (npr. naš hack), šaljemo nju, inače šaljemo naš InputValue
		proposeValue := n.InputValue
		if value != "" && value != n.InputValue {
			proposeValue = value //  Lider prihvata tu novu vrednost kao onu koju mora da predloži
			n.Log("!!! PAŽNJA !!! Kao lider pokušavam da nametnem vrednost: %s (umesto originalne: %s)", proposeValue, n.InputValue)
		} else {
			n.Log("Ja sam LIDER. Predlažem legitimnu vrednost: %s", proposeValue)
		}

		// Kreira se struktura poruke koja će biti poslata mreži
		msg := IBFTMessage{
			Type:     PrePrepare,
			Lambda:   n.Lambda,
			Round:    n.Round,
			Value:    proposeValue,
			SenderID: n.ID,
			ProofRC:  proof, // Ubacujemo dokaz u poruku
		}
		n.Broadcast(msg)

	} else { // za cvorove koji nisu lideri u ovoj rundi
		aktuelniLider := (n.Lambda + n.Round) % len(n.Validators) // Računa ID čvora koji bi trebalo da bude lider (da bi znao koga da čeka)
		n.Log("Ja sam validator. Lider za ovu rundu je Node %d. Cekam poruku...", aktuelniLider)
	}
}

// funkcija za formatirani ispis poruka u konzolu
func (n *IBFTNode) Log(format string, args ...interface{}) {
	// Kreira prefiks za svaku liniju loga koji pokazuje ID čvora i trenutnu rundu, radi lakšeg praćenja
	prefix := fmt.Sprintf("[Node %d][Round %d] ", n.ID, n.Round)
	// Ispisuje kompletnu poruku (prefiks + tekst poruke) u novi red
	fmt.Printf(prefix+format+"\n", args...)
}

// Računa koliko dugo čvor treba da čeka pre nego što proglasi da je runda propala
func (n *IBFTNode) GetTimerDuration() time.Duration {
	// Koristi "bit-shift" za računanje stepena dvojke
	// 5 sekundi * (2 na nivo runde) -> 5s, 10s, 20s...
	// Exponential Backoff – svakim neuspehom dajemo mreži više vremena
	return time.Duration(5*(1<<(n.Round-1))) * time.Second
}

// Poziva se kada tajmer otkuca nulu (niko nije postigao dogovor na vreme)
func (n *IBFTNode) OnTimerExpire() {
	// Ako je čvor ugašen ili je konsenzus već postignut, ignoriši tajmer
	if n.IsOffline || n.Decided {
		return
	}

	n.Round++
	n.Timer.Stop() // Zaustavljamo stari tajmer pre nego što pokrenemo novi
	n.Log("TAJMER ISTEKAO! Prelazim na Rundu %d. Saljem ROUND-CHANGE...", n.Round)

	// Briše (resetuje) sve glasove za Prepare i Commit iz prethodne runde
	n.PrepareVotes = make(map[string]map[int]bool)
	n.CommitVotes = make(map[string]map[int]bool)

	// Kreira novu poruku tipa RoundChange
	msg := IBFTMessage{
		Type:          RoundChange,
		Lambda:        n.Lambda,
		Round:         n.Round,
		SenderID:      n.ID,
		PreparedRound: n.PR, // Šaljemo šta smo zadnje pripremili
		PreparedValue: n.PV,
	}
	n.Broadcast(msg)
	// Ponovo pokreće tajmer, ali ovaj put sa dužim trajanjem (prema formuli odozgo)
	n.Timer.Reset(n.GetTimerDuration())
}

// Definiše funkciju koja simulira prestanak rada čvora
func (n *IBFTNode) Stop() {
	n.IsOffline = true
	n.Log("--- ČVOR SE UGASIO (CRASH) ---")
}

// HighestPrepared - Definiše funkciju koja iz prikupljenih RoundChange poruka izvlači vrednost koju lider treba da predloži
// Ovo je jedan od najbitnijih delova IBFT-a za očuvanje bezbednosti (Safety). Kada lider krene u novu rundu, on ne sme da predloži bilo šta,
// već ono što je bilo najbliže dogovoru u prošlosti
func (n *IBFTNode) SelectValueFromRC() string {
	highestPR := -1           // inicializacija
	highestPV := n.InputValue // Default ako niko ništa nije pripremio

	// uzima iz memorije sve RoundChange poruke koje su stigle od drugih čvorova za trenutnu rundu
	msgs, postojanje := n.RCStore[n.Round]
	// Ako slučajno nema nijedne poruke u memoriji, vraća početnu vrednost
	if !postojanje {
		return highestPV
	}

	// Prolazi kroz svaku primljenu RoundChange poruku
	for _, msg := range msgs {
		// Proverava da li je pošiljalac te poruke bio zaključan u rundi koja je kasnija (veća) od one koju smo do sada našli
		if msg.PreparedRound > highestPR && msg.PreparedValue != "" {
			highestPR = msg.PreparedRound // Ako jeste, ažurira highestPR na tu novu, veću rundu
			highestPV = msg.PreparedValue // Pamti vrednost koja je bila zaključana u toj rundi
		}
	}
	return highestPV // vraca "najjacu" vrednost
}

// Quorum računa potreban broj glasova za odluku (2f + 1)
func (n *IBFTNode) Quorum() int {
	totalNodes := len(n.Validators)
	f := (totalNodes - 1) / 3 // racuna max br malicioznih/neispravnih cvorova
	return 2*f + 1            // Vraća broj glasova koji garantuje da je većina poštenih čvorova postigla dogovor
}

// FPlusOne računa f + 1 (signal da je bar jedan pošten čvor video problem)
func (n *IBFTNode) FPlusOne() int {
	f := (len(n.Validators) - 1) / 3
	return f + 1
}

// Glavna funkcija koja drži čvor "živim" i uvek spremnim da odgovori na događaje
func (n *IBFTNode) Run() {
	n.Log("Pokrenut i ceka poruke ili tajmer...")
	// Beskonačna petlja. Čvor radi dokle god se program ne ugasi
	for {
		select {
		// Događaj 1: Stigla je nova poruka u sanduče (MsgChan)
		case msg := <-n.MsgChan:
			if !n.IsOffline { // Čvor obrađuje poruke samo ako NIJE offline
				n.HandleMessage(msg)
			}
		// Događaj 2: Sat je otkucao nulu (tajmer runde je istekao)
		case <-n.Timer.C:
			if !n.IsOffline { // Čvor reaguje na tajmer samo ako NIJE offline
				n.OnTimerExpire()
			}
		// Događaj 3: Ako se u ovom milisekundnom trenutku ništa ne dešava
		default:
			time.Sleep(10 * time.Millisecond) // Da ne opterecuje procesor dok ceka
		}
	}
}

// Ova funkcija se poziva kada je jedan blok uspešno završen (postignut konsenzus)
func (n *IBFTNode) NextInstance() {
	if n.IsOffline {
		return
	} // Ako je čvor ugašen, ne radi ništa i ne piši logove

	n.Lambda++  // povecavamo redni br bloka
	n.Round = 1 // resetujemo rundu na pocetnu
	n.PR = -1
	n.PV = ""
	n.Decided = false // Resetuje status odluke
	n.PrepareVotes = make(map[string]map[int]bool)
	n.CommitVotes = make(map[string]map[int]bool)
	n.RCStore = make(map[int]map[int]IBFTMessage)

	// Simuliramo da lider uzima nove podatke za novi blok
	n.InputValue = fmt.Sprintf("VREDNOST_ZA_BLOK_%d", n.Lambda)

	n.Log(">>> PRELAZIM NA SLEDECI BLOK: Lambda %d <<<", n.Lambda)
	// Pokreće proceduru konsenzusa za novi blok (Lambda, runda 1, novi podaci, bez dokaza jer je prva runda)
	n.Start(n.Lambda, 1, n.InputValue, nil)
}

// Lider koristi ovu funkciju da sakupi dokaze kojima će ubediti ostale čvorove da prihvate njegov predlog u rundi koja nije prva
// Vraća listu poruka (dokaz) i vrednost koja je opravdana
func (n *IBFTNode) GetRCProof() ([]IBFTMessage, string) {
	msgs := n.RCStore[n.Round] // Uzima sve RoundChange poruke koje su stigle za trenutnu rundu
	var proof []IBFTMessage    // Inicijalizuje prazan niz u koji će spakovati te poruke kao dokaz
	highestPR := -1
	highestPV := n.InputValue // podrazumevana vrednost

	//  Prolazi kroz sve prikupljene poruke od kolega validatora
	for _, m := range msgs {
		// Dodaje svaku poruku u niz dokaza (to su "potpisi" koji potvrđuju promenu runde)
		proof = append(proof, m)
		// LOGIKA PRIORITETA: Traži čvora koji je bio najdalje dogurao u prošlim (neuspešnim) rundama
		if m.PreparedRound > highestPR && m.PreparedValue != "" {
			highestPR = m.PreparedRound
			highestPV = m.PreparedValue
		}
	}
	return proof, highestPV // Vraća spisak svih poruka (kao fizički dokaz) i vrednost koju lider mora da koristi u svom PrePrepare predlogu
}

// GetValueFromProof izvlači opravdanu vrednost iz liste ProofRC poruka
// Ovu funkciju koriste validatori kada prime PrePrepare od lidera u rundama većim od 1, kako bi proverili da li lider "laže" ili predlaže ono što pravila nalažu
func (n *IBFTNode) GetValueFromProof(proof []IBFTMessage) string {
	highestPR := -1
	highestPV := n.InputValue // Ako niko ništa nije pripremio, liderova vrednost je OK

	// Prolazi kroz svaku poruku u dokazu koju je lider priložio uz svoj predlog
	for _, m := range proof {
		// KLJUČNO PRAVILO BEZBEDNOSTI: Traži se poruka sa najvećim brojem runde u kojoj je neka vrednost bila Prepared
		if m.PreparedRound > highestPR && m.PreparedValue != "" {
			highestPR = m.PreparedRound
			highestPV = m.PreparedValue // Ovo je vrednost koju lider mora da predloži da bi predlog bio validan
		}
	}
	return highestPV // Vraća opravdanu vrednost koju će validator uporediti sa onim što je lider stvarno poslao
}

// Pomoćna funkcija za lep ispis dokaza
func (n *IBFTNode) FormatProof(proof []IBFTMessage) string {
	// Ako je dokaz prazan, vraća samo prazne zagrade
	if len(proof) == 0 {
		return "[]"
	}
	res := "["
	// Prolazi kroz svaku poruku u dokazu
	for _, m := range proof {
		pvPrikaz := m.PreparedValue
		if pvPrikaz == "" {
			pvPrikaz = "⊥" // Simbol za prazno (bottom)
		}
		// Dodaje u string podatke o čvoru: ko je on (V), u kojoj rundi je bio zaključan (PR) i na kojoj vrednosti (PV)
		res += fmt.Sprintf("{V%d: PR=%d, PV=%s} ", m.SenderID, m.PreparedRound, pvPrikaz)
	}
	res += "]"
	return res
}
