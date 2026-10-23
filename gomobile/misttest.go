// Package misttest provides a gomobile-compatible API for Mist UDP handshake testing.
// Lab only: requires `-tags mist_unsafe_initial`.
package misttest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"misttest/mistcore"
)

// TestResult holds the handshake test output.
type TestResult struct {
	Success bool
	Log     string
}

// RunHandshake performs Mist UDP handshake and PING/PONG test.
// Returns a TestResult with logs.
func RunHandshake(serverAddr, cidHex, keyB64 string) *TestResult {
	var logs strings.Builder
	log := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		logs.WriteString(msg + "\n")
	}

	log("=== Mist UDP Test ===")
	log("Server: %s", serverAddr)
	log("CID: %s", cidHex)

	// Parse CID.
	cidBytes, err := hex.DecodeString(cidHex)
	if err != nil || len(cidBytes) != 16 {
		return &TestResult{false, logs.String() + "ERROR: bad cid\n"}
	}
	var cid [16]byte
	copy(cid[:], cidBytes)

	// Parse K_auth.
	keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(keyBytes) != 32 {
		return &TestResult{false, logs.String() + "ERROR: bad key\n"}
	}
	var kAuth [32]byte
	copy(kAuth[:], keyBytes)

	// Resolve server.
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: resolve: %v\n", err)}
	}

	// Create UDP socket.
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: listen: %v\n", err)}
	}
	defer conn.Close()

	// --- Handshake ---
	hsStart := time.Now()

	ephPriv, ephPub, err := mistcore.X25519Keypair()
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: keypair: %v\n", err)}
	}

	// Build AUTH plaintext.
	authPlain := make([]byte, 45)
	authPlain[0] = 0x02
	binary.BigEndian.PutUint64(authPlain[1:9], uint64(time.Now().Unix()))
	copy(authPlain[9:41], ephPub[:])

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: nonce: %v\n", err)}
	}

	mac := hmac.New(sha256.New, kAuth[:])
	mac.Write(nonce[:])
	var handshakeCID [16]byte
	copy(handshakeCID[:], mac.Sum(nil)[:16])

	ciphertext, err := mistcore.UDPSeal(&kAuth, nonce, authPlain, handshakeCID[:])
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: seal: %v\n", err)}
	}

	authWire := make([]byte, 0, 16+24+len(ciphertext))
	authWire = append(authWire, handshakeCID[:]...)
	authWire = append(authWire, nonce[:]...)
	authWire = append(authWire, ciphertext...)

	var scid [8]byte
	if _, err := rand.Read(scid[:]); err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: scid: %v\n", err)}
	}
	var dcid [8]byte

	codec := &mistcore.RandomCiphertextCodec{}
	initial, err := codec.SealInitial(authWire, dcid, scid, 0)
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: seal initial: %v\n", err)}
	}

	log("Sending Initial (%d bytes)...", len(initial))

	var response []byte
	retransmits := 0
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			retransmits++
			if _, err := rand.Read(nonce[:]); err != nil {
				break
			}
			if _, err := rand.Read(scid[:]); err != nil {
				break
			}
			mac := hmac.New(sha256.New, kAuth[:])
			mac.Write(nonce[:])
			copy(handshakeCID[:], mac.Sum(nil)[:16])
			ciphertext, _ = mistcore.UDPSeal(&kAuth, nonce, authPlain, handshakeCID[:])
			authWire = authWire[:0]
			authWire = append(authWire, handshakeCID[:]...)
			authWire = append(authWire, nonce[:]...)
			authWire = append(authWire, ciphertext...)
			initial, _ = codec.SealInitial(authWire, dcid, scid, 0)
			log("  retransmit #%d", attempt)
		}
		if _, err := conn.WriteToUDP(initial, udpAddr); err != nil {
			return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: send: %v\n", err)}
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil {
			response = buf[:n]
			break
		}
	}
	if response == nil {
		return &TestResult{false, logs.String() + "FAIL: handshake timeout (4 attempts)\n"}
	}

	hsElapsed := time.Since(hsStart)
	log("Got AUTH_OK (%d bytes) in %v (retransmits: %d)", len(response), hsElapsed, retransmits)

	// Parse AUTH_OK.
	authOKWire, respDCID, _, _, err := codec.OpenInitialResponse(response)
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: parse auth_ok: %v\n", err)}
	}
	if respDCID != scid {
		return &TestResult{false, logs.String() + "FAIL: DCID mismatch\n"}
	}
	var okNonce [24]byte
	copy(okNonce[:], authOKWire[:24])
	okCipher := authOKWire[24:]
	okPlain, err := mistcore.UDPOpen(&kAuth, okNonce, okCipher, nil)
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: auth_ok decrypt: %v\n", err)}
	}
	var srvEphPub [32]byte
	copy(srvEphPub[:], okPlain[0:32])
	var sessionID [16]byte
	copy(sessionID[:], okPlain[32:48])

	shared, err := mistcore.X25519Shared(&ephPriv, &srvEphPub)
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: shared: %v\n", err)}
	}
	kC2S, kS2C := mistcore.DeriveSessionKeys(ephPub, srvEphPub, shared)
	session := mistcore.NewUDPSession(sessionID, kC2S, kS2C, udpAddr, codec)

	log("Handshake OK! Session: %x", sessionID[:8])
	log("Handshake time: %v", hsElapsed)

	// --- PING/PONG ---
	log("--- PING/PONG ---")
	pingStart := time.Now()
	pingFrame := mistcore.EncodeUDPFrame(mistcore.UDPFramePing, 0, []byte("hello-mist-udp"))
	pkt, err := session.SealPacket(mistcore.DirC2S, [][]byte{pingFrame})
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: seal ping: %v\n", err)}
	}
	if _, err := conn.WriteToUDP(pkt, udpAddr); err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: send ping: %v\n", err)}
	}
	log("Sent PING (%d bytes)", len(pkt))

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("FAIL: PONG timeout: %v\n", err)}
	}
	pingElapsed := time.Since(pingStart)
	frames, _, err := session.OpenPacket(mistcore.DirS2C, buf[:n])
	if err != nil {
		return &TestResult{false, logs.String() + fmt.Sprintf("ERROR: open pong: %v\n", err)}
	}
	gotPong := false
	for _, f := range frames {
		if f.Type == mistcore.UDPFramePong {
			gotPong = true
			break
		}
	}
	if !gotPong {
		return &TestResult{false, logs.String() + "FAIL: no PONG\n"}
	}

	log("Got PONG! RTT: %v", pingElapsed)
	log("=== TEST PASSED ===")
	return &TestResult{true, logs.String()}
}
