package main

import (
	"fmt"
	"ibft-projekat/consensus"
	"time"
)

func main() {
	for {
		fmt.Println("\n==============================================")
		fmt.Println("   IBFT CONSENSUS SIMULATOR - IZABERITE SCENARIO")
		fmt.Println("==============================================")
		fmt.Println("1. Normalno izvrsavanje (Sve OK)")
		fmt.Println("2. Timeout u 'New Round' (Lider pao odmah)")
		fmt.Println("3. Timeout u 'Pre-prepared' (Nema kvoruma za Prepare)")
		fmt.Println("4. Timeout u 'Prepared' (Nema kvoruma za Commit)")
		fmt.Println("5. Timeout u 'Committed' (Greska pri upisu u bazu)")
		fmt.Println("6. Vizantijski lider (Lider laze)")
		fmt.Println("7. Pokusaj krsenja bezbednosti (Justify Test)")
		fmt.Println("8. Izlaz")
		fmt.Print("Vas izbor: ")

		var izbor int
		fmt.Scanln(&izbor)
		if izbor == 8 {
			break
		}

		// Provera da li je unet nepostojeći scenario
		if izbor < 1 || izbor > 8 {
			fmt.Println("Nepostojeci izbor, pokusajte ponovo.")
			continue
		}
		pokreniSimulaciju(izbor)
	}
}

func pokreniSimulaciju(scenario int) {
	validatorIDs := []int{0, 1, 2, 3}
	nodes := make(map[int]*consensus.IBFTNode) // Pravi mapu u kojoj ćemo čuvati objekte čvorova

	// Kreira 4 nova čvora sa početnom vrednošću VREDNOST_ZA_BLOK_1
	for _, id := range validatorIDs {
		nodes[id] = consensus.NewIBFTNode(id, "VREDNOST_ZA_BLOK_1", validatorIDs)
	}
	// Povezuje čvorove. Svaki čvor dobija kanale (adrese) svih ostalih da bi mogli da komuniciraju
	for _, node := range nodes {
		for id, peer := range nodes {
			node.PeerChans[id] = peer.MsgChan
		}
	}

	// "podela" javnih ključeva
	for _, n1 := range nodes {
		for _, n2 := range nodes {
			// Svaki čvor (n1) dobija javni ključ od svakog drugog čvora (n2)
			n1.PeerPublicKeys[n2.ID] = &n2.PrivateKey.PublicKey
		}
	}

	// Pokreće svaki čvor u posebnoj gorutini (thread-u) tako da svi rade istovremeno
	for _, node := range nodes {
		go node.Run()
	}

	// Kratka pauza da se svi čvorovi stabilizuju pre početka akcije
	time.Sleep(200 * time.Millisecond)

	switch scenario {
	case 1:
		fmt.Println("\n>>> SCENARIO 1: Sve radi ispravno...")
		// Svi čvorovi započinju prvu rundu
		// Node koji po formuli (Lambda+Round)%4 ispadne lider, taj će započeti.
		for _, n := range nodes {
			go n.Start(1, 1, "VREDNOST_ZA_BLOK_1", nil)
		}

	case 2:
		fmt.Println("\n>>> SCENARIO 2: Lider Node 2 je mrtav. Cekamo Round Change...")
		// Odmah gasimo čvor 2 - Lider je "mrtav"
		// stali čvorovi će čekati poruku od njega, ali pošto je on lider i nema ga, aktiviraće se njihovi tajmeri i preći će u Rundu 2
		nodes[2].Stop()

		// Pokrećemo proces na ostalim čvorovima (0, 1, 3)
		for _, n := range nodes {
			if !n.IsOffline {
				go n.Start(1, 1, "VREDNOST_ZA_BLOK_1", nil)
			}
		}

	case 3:
		fmt.Println("\n>>> SCENARIO 3: Node 0 i 3 padaju pre pocetka. Lider nece imati kvorum...")
		// Pošto su za kvorum potrebna 3 glasa, a samo su 2 čvora živa, dogovor nikada neće biti postignut
		nodes[0].Stop()
		nodes[3].Stop()
		time.Sleep(100 * time.Millisecond)

		// Pokrećemo sve preostale čvorove (Node 1 i Node 2)
		for _, n := range nodes {
			if !n.IsOffline {
				go n.Start(1, 1, "VREDNOST_ZA_BLOK_1", nil)
			}
		}

		time.Sleep(6 * time.Second) // Sačekamo da tajmer istekne i ispiše promenu runde
		fmt.Println("\n[Scenario 3: Videli smo pokretanje Round Change, zaustavljam cvorove...]")
		for _, n := range nodes {
			n.Stop()
		} // Gasimo ih da ne idu u rundu 3, 4...

	case 4:
		fmt.Println("\n>>> SCENARIO 4: Svi se pripreme, pa Node 0 i 3 padnu pre slanja Commit-a...")
		// Testiramo šta se dešava kada mreža ostane bez kvoruma u najkritičnijem trenutku

		// Aktiviramo automatski kvar za čvorove 0 i 3
		nodes[0].Scenario4Fail = true
		nodes[3].Scenario4Fail = true

		// Pokreni SVE čvorove da bi pravi lider (Node 2) poslao predlog
		for _, n := range nodes {
			go n.Start(1, 1, "VREDNOST_ZA_BLOK_1", nil)
		}

		// Pusti ostatak mreže da pokuša da završi (i da ne uspe zbog kvoruma)
		time.Sleep(7 * time.Second)

	case 5:
		fmt.Println("\n>>> SCENARIO 5: Svi postignu kvorum, ali Lideru puca baza pri upisu...")

		// Svim cvorovima palimo simulaciju greske pri upisu
		for _, n := range nodes {
			n.SimulateInsertError = true
		}

		for _, n := range nodes {
			go n.Start(1, 1, "VREDNOST_ZA_BLOK_1", nil)
		}

		time.Sleep(7 * time.Second) // Pustimo da prođe jedna runda i pukne baza
		fmt.Println("\n[Scenario 5: Demonstrirano pucanje baze, prekidam simulaciju...]")
		for _, n := range nodes {
			n.Stop()
		}

	case 6:
		fmt.Println("\n>>> SCENARIO 6: Vizantijski lider (Node 2) salje razlicite vrednosti...")

		// Prolazi kroz sve čvorove da im postavi uloge za prvu rundu
		for _, n := range nodes {
			// Računa ko je po protokolu lider za Rundu 1 (to je Node 2)
			aktuelniLider := (n.Lambda + n.Round) % len(n.Validators)
			if n.ID == aktuelniLider {
				n.Log("Ja sam LIDER. (Spremam se da šaljem različite poruke...)")
			} else {
				n.Log("Ja sam validator. Lider za ovu rundu je Node %d. Cekam poruku...", aktuelniLider)
			}
		}

		time.Sleep(100 * time.Millisecond)

		// Lider (Node 2) šalje Node-u 0 i 2 VREDNOST X
		msg1 := consensus.IBFTMessage{
			Type: "PRE-PREPARE", Lambda: 1, Round: 1, Value: "VREDNOST_ZA_BLOK_1_X", SenderID: 2,
		}
		nodes[2].SignMessage(&msg1) // <-- KLJUČNI DODATAK: Node 2 potpisuje svoju laž

		// Lider (Node 2) šalje Node-u 3 i 1 VREDNOST Y
		msg2 := consensus.IBFTMessage{
			Type: "PRE-PREPARE", Lambda: 1, Round: 1, Value: "VREDNOST_ZA_BLOK_1_Y", SenderID: 2,
		}
		nodes[2].SignMessage(&msg2) // <-- KLJUČNI DODATAK

		nodes[0].MsgChan <- msg1
		nodes[2].MsgChan <- msg1
		nodes[3].MsgChan <- msg2
		nodes[1].MsgChan <- msg2

		fmt.Println("Lider (Node 2) je podelio mrežu: pola vidi X, pola Y vrednost. Mreza ne bi smela da postigne kvorum!")
		time.Sleep(7 * time.Second)

	case 7:
		fmt.Println("\n>>> SCENARIO 7: Test bezbednosti (Justify). Maliciozni lider pokušava prevaru...")

		// RESETUJEMO SVE ČVOROVE (Za svaki slučaj)
		for _, n := range nodes {
			n.IsOffline = false
			n.Scenario7R1Fail = false
		}

		// 1. Čvor 2 je offline (on čeka svoju Rundu 2 da postane zlonamerni lider)
		nodes[2].IsOffline = true

		// 2. Čvorovima 0 i 1 palimo kočnicu (puknuće čim se zaključaju)
		nodes[0].Scenario7R1Fail = false
		nodes[1].Scenario7R1Fail = true

		// 3. Lider Node 1 pokreće legitimnu Rundu 1
		fmt.Println("[KORAK 1: Runda 1 kreće normalno. Čvorovi 0, 1 i 3 treba da se zaključaju...]")
		nodes[1].Start(1, 1, "VREDNOST_ZA_BLOK_1", nil)

		// 4. Čekamo dovoljno da se svi zaključaju (da prime PrePrepare i pošalju Prepare glasove)
		time.Sleep(2 * time.Second)

		fmt.Println("\n[KORAK 2: Čvor 1 je zaključan i pao je. Node 0 i 3 je ostao sam i ZAKLJUČAN.]")
		fmt.Println("[Sada budimo Node 2 (on je lider za Rundu 2) i čekamo Timeout...]")

		nodes[2].IsOffline = false

		// 5. Čekamo da tajmer istekne i da pređu u Rundu 2 gde je Čvor 2 lider
		fmt.Println("[Čekamo da tajmeri isteknu i da Čvor 2 postane lider i pokuša prevaru...]")
		time.Sleep(15 * time.Second)
	}

	// Pustamo simulator onoliko koliko smo procenili da treba
	time.Sleep(20 * time.Second)

	fmt.Println("\n>>> CISCENJE SCENARIJA: Gasim stare cvorove...")
	for _, n := range nodes {
		n.Stop() // Postavlja IsOffline = true, pa cvorovi prestaju da procesiraju
	}

	// Opciono: mala pauza da se terminal "smiri" pre menija
	time.Sleep(500 * time.Millisecond)
	fmt.Println("[Simulacija zavrsena. Vracanje na meni...]")
}
