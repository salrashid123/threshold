package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"

	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/golang/glog"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lestrrat/go-jwx/jwk"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/share"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/vault/sdk/helper/xor"

	"github.com/golang-jwt/jwt/v5"

	// for testing: https://github.com/salrashid123/confidential_space/tree/main/misc/testtoken
	tk "github.com/salrashid123/confidential_space/misc/testtoken"
	"github.com/salrashid123/threshold/generate/common"
	"golang.org/x/exp/slices"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
)

const (
	lru_size = 200
)

var (
	listen = flag.String("listen", ":8081", "address to listen on (default :8081)")

	jwksURL = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"

	tlsCert                              = flag.String("tlsCert", "certs/server.crt", "TLS Cert")
	tlsKey                               = flag.String("tlsKey", "certs/server.key", "TLS Key")
	tlsCA                                = flag.String("tlsCA", "certs/tls-ca-chain.pem", "TLS CA")
	useTestIssuer                        = flag.Bool("useTestIssuer", false, "Use Testing attestation token Issuer")
	clientCertCA                         = flag.String("clientCertCA", "certs/client-ca.crt", "Client TLS CA")
	custom_attestation_token_path        = flag.String("custom_attestation_token_path", "/run/container_launcher/teeserver.sock", "Path to Custom Attestation socket")
	marshal_custom_token_string_as_array = flag.Bool("marshal_custom_token_string_as_array", false, "Try to parse audience and eat_token as string array even if single string")

	jwtSet *jwk.Set

	mu sync.Mutex

	//registry = make(map[string]common.KeyState)
	registry *lru.Cache[string, *common.KeyState]
)

const (
	TOKEN_TYPE_OIDC        string = "OIDC"
	TOKEN_TYPE_UNSPECIFIED string = "UNSPECIFIED"
	testJWK                       = "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/certs"
)

type customToken struct {
	Audience  string   `json:"audience"`
	Nonces    []string `json:"nonces"`
	TokenType string   `json:"token_type"`
}

type event struct {
	PeerCertificates     []*x509.Certificate
	PeerPublicKeyHash    string
	EKM                  string
	PublicKeyXOR         string
	ParticipantKeyHashes []string
	RemoteIP             net.IP
}

type server struct{}

type contextKey string

const contextEventKey contextKey = "event"

func eventsMiddleware(h http.Handler) http.Handler {
	glog.V(30).Infof("--------------------------------")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Userip is not host:port", http.StatusBadGateway)
			return
		}
		userIP := net.ParseIP(ip)
		if userIP == nil {
			http.Error(w, "error parsing remote IP", http.StatusBadGateway)
			return
		}

		if len(r.TLS.VerifiedChains) == 0 {
			glog.Errorf("Unverified client certificate from: %s\n", ip)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		ekm, err := r.TLS.ExportKeyingMaterial(common.EKMLabel, nil, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		glog.V(40).Infof("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

		if len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "Peer certificate not provided", http.StatusBadRequest)
			return
		}

		clientCert := r.TLS.VerifiedChains[0][0]
		// v := clientCert.Subject.CommonName
		// sn := clientCert.SerialNumber

		publicKeyDer, err := x509.MarshalPKIXPublicKey(clientCert.PublicKey)
		if err != nil {
			http.Error(w, "Error extracting peer certificate DER", http.StatusBadRequest)
			return
		}

		ha := sha256.New()
		ha.Write(publicKeyDer)
		hsh := ha.Sum(nil)
		glog.V(40).Infof("Client Certificate Public Key Hash: %s\n", hex.EncodeToString(hsh))

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			glog.Errorf(fmt.Sprintf("Error reading body %v\n", err))
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		r.Body.Close() //  must close
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		var post common.BaseRequest
		err = json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&post)
		if err != nil {
			glog.Errorf("Error parsing POST data")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var participantKeyHash []string
		xorHash := make([]byte, 32)
		for _, r := range post.ParticipantPublicKeys {

			_, err := x509.ParsePKIXPublicKey(r)
			if err != nil {
				glog.Errorf("     Error parsing public key for   %v", err)
				http.Error(w, fmt.Sprintf("Error parsing public key %v\n", err), http.StatusBadRequest)
				return
			}

			h := sha256.New()
			h.Write(r)
			hsh2 := h.Sum(nil)

			xorHash, err = xor.XORBytes(xorHash, hsh2)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error hashing public keys fingerprints %v\n", err), http.StatusBadRequest)
				return
			}

			glog.V(40).Infof("Participant Public Key hashes %s\n", hex.EncodeToString(hsh2))
			participantKeyHash = append(participantKeyHash, hex.EncodeToString(hsh2))
		}

		if !slices.Contains(participantKeyHash, hex.EncodeToString(hsh)) {
			glog.Errorf("Error verifying peer with public key set")
			http.Error(w, "Error verifying peer with public key set", http.StatusBadRequest)
			return
		}
		glog.V(40).Infof("Client Certificate XOR value %s", hex.EncodeToString(xorHash))

		event := &event{
			PeerCertificates:     r.TLS.PeerCertificates,
			PeerPublicKeyHash:    hex.EncodeToString(hsh),
			EKM:                  hex.EncodeToString(ekm),
			PublicKeyXOR:         hex.EncodeToString(xorHash),
			ParticipantKeyHashes: participantKeyHash,
			RemoteIP:             userIP,
		}
		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}
func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

// establish a TLS connection with the TEE
//
//	the response back to the client will contain the EKM value encoded in the eat_nonce
//	the audience value just happens to be the client certificates hash
//	  (yes, the aud: bit with client cert this isn't at all useful, i was just looking for a reason to use aud field)
func connectHandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)

	glog.V(20).Info("/connect")
	glog.V(30).Infof("   from  %s\n", val.RemoteIP.String())

	var post common.ConnectRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, post.Nonce, val.PublicKeyXOR},
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, post.Nonce, val.PublicKeyXOR},
			TokenType: TOKEN_TYPE_OIDC,
		}
		customTokenValue, err = getCustomAttestation(ttsa)
	}

	if err != nil {
		glog.Errorf("     Error creating Custom JWT %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&common.ConnectResponse{
		Nonce:          post.Nonce,
		AttestationJWT: customTokenValue,
	})
}

func createMarkerHandler(w http.ResponseWriter, r *http.Request) {
	glog.V(20).Info("/create_marker")
	val := r.Context().Value(contextKey("event")).(event)

	var post common.CreateMarkerRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var ks []*common.KeyShare

	for _, r := range post.ParticipantPublicKeys {
		_, err := x509.ParsePKIXPublicKey(r)
		if err != nil {
			glog.Errorf("     Error parsing public key for   %v", err)
			http.Error(w, fmt.Sprintf("Error parsing public key %v\n", err), http.StatusBadRequest)
			return
		}
		kr := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: r})
		glog.V(30).Infof("Participant Public Key: \n%s\n", kr)

		h := sha256.New()
		h.Write(r)
		hsh := h.Sum(nil)

		k := &common.KeyShare{
			PublicKey:     r,
			PublicKeyHash: hsh,
		}
		ks = append(ks, k)
	}

	id := uuid.New()
	uid := id.String()
	glog.V(20).Infof("  created %s", uid)

	ds, err := hex.DecodeString(val.PublicKeyXOR)
	if err != nil {
		glog.Errorf("     Error decoding hex public key xor  %v", err)
		http.Error(w, fmt.Sprintf("Error decoding hex public key xor%v\n", err), http.StatusBadRequest)
		return
	}

	// now update the 'database' with the marker specifications

	mu.Lock()
	defer mu.Unlock()

	// registry[uid] = common.KeyState{
	// T:            post.T,
	// N:            post.N,
	// Marker:       uid,
	// KeyShares:    ks,
	// DataToSign:   post.DataToSign,
	// Quorum:       0,
	// PublicKeyXOR: ds,
	// }
	registry.Add(uid, &common.KeyState{
		T:                  post.T,
		N:                  post.N,
		Marker:             uid,
		KeyShares:          ks,
		DataToSign:         post.DataToSign,
		Quorum:             0,
		PublicKeyXOR:       ds,
		ParticipantKeyHash: val.ParticipantKeyHashes,
	})

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, uid, val.PublicKeyXOR},
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, uid, val.PublicKeyXOR},
			TokenType: TOKEN_TYPE_OIDC,
		}
		customTokenValue, err = getCustomAttestation(ttsa)
	}

	if err != nil {
		glog.Errorf("     Error creating eat token %v", err)
		http.Error(w, fmt.Sprintf("Error creating eat token %v\n", err), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&common.CreateMarkerResponse{
		Uid:            uid,
		AttestationJWT: customTokenValue,
	})
}

func getMarkerHandler(w http.ResponseWriter, r *http.Request) {

	glog.V(20).Info("/get_marker")

	val := r.Context().Value(contextKey("event")).(event)

	var post common.GetMarkerRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	glog.V(20).Infof("  for uid %s", post.Uid)

	mu.Lock()
	defer mu.Unlock()

	e, ok := registry.Get(post.Uid)
	//e, ok := registry[post.Uid]
	if !ok {
		glog.Errorf("UID not registered")
		http.Error(w, fmt.Sprintf("UID not registered"), http.StatusBadRequest)
		return
	}

	if !slices.Contains(e.ParticipantKeyHash, val.PeerPublicKeyHash) {
		glog.Errorf("Error verifying peer with public key set")
		http.Error(w, "Error verifying peer with public key set", http.StatusBadRequest)
		return
	}

	if val.PublicKeyXOR != hex.EncodeToString(e.PublicKeyXOR) {
		glog.Errorf("Provided list of public keys do not match")
		http.Error(w, "list of public keys do not match", http.StatusBadRequest)
		return
	}

	var signatures []common.SignatureSet
	for _, k := range e.KeyShares {
		s := common.SignatureSet{
			ParticipantPublicKey: k.PublicKeyHash,
			ParticipantSignature: k.ProvidedSignature,
		}
		signatures = append(signatures, s)
	}

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, e.Marker, hex.EncodeToString(e.PublicKeyXOR)},
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, e.Marker, hex.EncodeToString(e.PublicKeyXOR)},
			TokenType: TOKEN_TYPE_OIDC,
		}
		customTokenValue, err = getCustomAttestation(ttsa)
	}
	if err != nil {
		glog.Errorf("     Error creating eat token %v", err)
		http.Error(w, fmt.Sprintf("Error creating eat token %v\n", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&common.GetMarkerResponse{
		Uid:             e.Marker,
		PublicKeyHashes: val.ParticipantKeyHashes,
		T:               e.T,
		N:               e.N,
		Quorum:          e.Quorum,
		DataToSign:      e.DataToSign,
		AttestationJWT:  customTokenValue,
		SignatureSet:    signatures,
	})
}

func signMarkerHandler(w http.ResponseWriter, r *http.Request) {

	glog.V(20).Info("/sign_marker")

	val := r.Context().Value(contextKey("event")).(event)

	var post common.SignMarkerRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	glog.V(20).Infof("  for uid %s", post.Uid)

	mu.Lock()
	defer mu.Unlock()

	e, ok := registry.Get(post.Uid)
	//e, ok := registry[post.Uid]
	if !ok {
		glog.Errorf("UID not registered")
		http.Error(w, fmt.Sprintf("UID not registered"), http.StatusBadRequest)
		return
	}
	var publicKey crypto.PublicKey

	if !slices.Contains(e.ParticipantKeyHash, val.PeerPublicKeyHash) {
		glog.Errorf("Error verifying peer with public key set")
		http.Error(w, "Error verifying peer with public key set", http.StatusBadRequest)
		return
	}

	if val.PublicKeyXOR != hex.EncodeToString(e.PublicKeyXOR) {
		glog.Errorf("Provided list of public keys do not match")
		http.Error(w, "list of public keys do not match", http.StatusBadRequest)
		return
	}

	for _, r := range e.KeyShares {
		if hex.EncodeToString(r.PublicKeyHash) == val.PeerPublicKeyHash {
			publicKey, err = x509.ParsePKIXPublicKey(r.PublicKey)
			if err != nil {
				glog.Errorf("     Error parsing public key for   %v", err)
				http.Error(w, fmt.Sprintf("Error parsing public key %v\n", err), http.StatusBadRequest)
				return
			}
			break
		}
		k := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: r.PublicKey})
		glog.V(30).Infof("Participant Public Key: \n%s\n", k)
	}
	if publicKey == nil {
		glog.Errorf("     Error finding public key ")
		http.Error(w, fmt.Sprintf("Error finding\n"), http.StatusBadRequest)
		return
	}

	pkey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		glog.Errorf("Error converting publickey to rsa public key")
		http.Error(w, "Error converting publickey to rsa public key", http.StatusInternalServerError)
		return
	}
	h := sha256.New()
	h.Write(e.DataToSign)
	msgHashSum := h.Sum(nil)

	err = rsa.VerifyPKCS1v15(pkey, crypto.SHA256, msgHashSum, post.Signature)
	if err != nil {
		glog.Errorf("Could not verify marker signature %v", err)
		http.Error(w, fmt.Sprintf("Could not verify marker signature %v", err), http.StatusInternalServerError)
		return
	}
	glog.V(30).Infof("Verified marker signature for marker %s", post.Uid)

	for i, k := range e.KeyShares {
		if hex.EncodeToString(k.PublicKeyHash) == val.PeerPublicKeyHash {
			if len(k.ProvidedSignature) != 0 {
				glog.Errorf("Signature already provided for participant")
				http.Error(w, "Signature already provided for participant", http.StatusBadRequest)
				return
			} else {
				e.KeyShares[i].ProvidedSignature = post.Signature
			}
		}
	}

	e.Quorum++

	if e.Quorum == e.N {
		glog.V(10).Infof("Quorum reached; Generating Threshold KeyShares for marker %s\n", e.Marker)

		suite := bn256.NewSuite()
		var pp [][]byte
		var ps [][]byte

		secret := suite.G1().Scalar().Pick(suite.RandomStream())
		priPoly := share.NewPriPoly(suite.G2(), int(e.T), secret, suite.RandomStream())
		pubPoly := priPoly.Commit(suite.G2().Point().Base())

		sharePubbin, err := pubPoly.Commit().MarshalBinary()
		if err != nil {
			glog.Errorf("Error marshalling publicPoly binary %v\n", err)
			http.Error(w, fmt.Sprintf(" Error marshalling publicPoliy binary %v\n", err), http.StatusInternalServerError)
			return
		}

		pubstr := base64.StdEncoding.EncodeToString(sharePubbin)
		glog.V(40).Infof("Threshold Public Key:  %s for marker %s\n", pubstr, e.Marker)
		e.SharePublicKey = sharePubbin

		/// create key shares
		for _, x := range pubPoly.Shares(int(e.N)) {
			pval, err := x.V.MarshalBinary()
			if err != nil {
				glog.Errorf("Error marshalling publicPolicy binary %v\n", err)
				http.Error(w, fmt.Sprintf(" Error marshalling publicPolicy binary %v\n", err), http.StatusInternalServerError)
			}
			glog.V(40).Infof("Created Public Share index [%d] with hash [%s]", x.I, base64.StdEncoding.EncodeToString(x.Hash(suite)))
			//log.Printf("  Public Key for Share Index:  %s\n", base64.StdEncoding.EncodeToString(pval))
			pp = append(pp, pval)
		}

		for _, x := range priPoly.Shares(int(e.N)) {
			pval, err := x.V.MarshalBinary()
			if err != nil {
				glog.Errorf("Error creating private shares %v\n", err)
				http.Error(w, fmt.Sprintf(" Error creating private shares %v\n", err), http.StatusInternalServerError)
				return
			}
			glog.V(40).Infof("Created Private Share index [%d] with hash [%s]", x.I, base64.StdEncoding.EncodeToString(x.Hash(suite)))
			ps = append(ps, pval)
		}

		for i, ks := range e.KeyShares {
			//pubPem, _ := pem.Decode(ks.PublicKey)
			pkey, err := x509.ParsePKIXPublicKey(ks.PublicKey)
			if err != nil {
				glog.Errorf("Error parsing public encryption key %v\n", err)
				http.Error(w, fmt.Sprintf(" Error parsing public encryption key %v\n", err), http.StatusInternalServerError)
				return
			}

			pu, ok := pkey.(*rsa.PublicKey)
			if !ok {
				glog.Errorf("Error reading publicKey %v\n", err)
				http.Error(w, fmt.Sprintf("Error encrypting secretKey %v\n", err), http.StatusInternalServerError)
				return
			}
			hash := sha256.New()
			secretCipherText, err := rsa.EncryptOAEP(hash, rand.Reader, pu, ps[i], []byte(e.Marker))
			if err != nil {
				glog.Errorf("Error encrypting secretKey %v\n", err)
				http.Error(w, fmt.Sprintf("Error encrypting secretKey %v\n", err), http.StatusInternalServerError)
				return
			}
			e.KeyShares[i].Index = i
			e.KeyShares[i].EncryptedSharePrivateKey = secretCipherText
			e.KeyShares[i].SharePublic = pp[i]
		}
	}

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, e.Marker, hex.EncodeToString(e.PublicKeyXOR)},
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, e.Marker, hex.EncodeToString(e.PublicKeyXOR)},
			TokenType: TOKEN_TYPE_OIDC,
		}
		customTokenValue, err = getCustomAttestation(ttsa)
	}
	if err != nil {
		glog.Errorf("     Error creating eat token %v", err)
		http.Error(w, fmt.Sprintf("Error creating eat token %v\n", err), http.StatusBadRequest)
		return
	}

	//registry[post.Uid] = e
	registry.Add(post.Uid, e)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&common.SignMarkerResponse{
		Uid:            e.Marker,
		AttestationJWT: customTokenValue,
	})
}

func getKeyHandler(w http.ResponseWriter, r *http.Request) {

	glog.V(20).Info("/get_key")

	val := r.Context().Value(contextKey("event")).(event)

	var post common.GetKeyRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	glog.V(20).Infof("  for uid %s", post.Uid)

	mu.Lock()
	defer mu.Unlock()

	e, ok := registry.Get(post.Uid)
	//e, ok := registry[post.Uid]
	if !ok {
		glog.Errorf("UID not registered")
		http.Error(w, fmt.Sprintf("UID not registered"), http.StatusBadRequest)
		return
	}

	if !slices.Contains(e.ParticipantKeyHash, val.PeerPublicKeyHash) {
		glog.Errorf("Error verifying peer with public key set")
		http.Error(w, "Error verifying peer with public key set", http.StatusBadRequest)
		return
	}

	if val.PublicKeyXOR != hex.EncodeToString(e.PublicKeyXOR) {
		glog.Errorf("Provided list of public keys do not match")
		http.Error(w, "list of public keys do not match", http.StatusBadRequest)
		return
	}

	if e.N != e.Quorum {
		glog.Errorf("Quorum not reached")
		http.Error(w, "Quorum not reached", http.StatusPreconditionFailed)
		return
	}

	var sp []byte
	var espr []byte
	var index int
	for _, k := range e.KeyShares {
		if hex.EncodeToString(k.PublicKeyHash) == val.PeerPublicKeyHash {
			sp = k.SharePublic
			espr = k.EncryptedSharePrivateKey
			index = k.Index
		}
	}

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, e.Marker, val.PublicKeyXOR},
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  val.PeerPublicKeyHash,
			Nonces:    []string{val.EKM, e.Marker, val.PublicKeyXOR},
			TokenType: TOKEN_TYPE_OIDC,
		}
		customTokenValue, err = getCustomAttestation(ttsa)
	}
	if err != nil {
		glog.Errorf("     Error creating eat token %v", err)
		http.Error(w, fmt.Sprintf("Error creating eat token %v\n", err), http.StatusBadRequest)
		return
	}

	if len(sp) == 0 || len(espr) == 0 {
		glog.Errorf("     Threshold keypair not found for peer")
		http.Error(w, "Threshold keypair not found for peer", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&common.GetKeyResponse{
		Uid:                   e.Marker,
		ThresholdPublic:       e.SharePublicKey,
		SharePublic:           sp,
		Index:                 index,
		EncryptedSharePrivate: espr,
		AttestationJWT:        customTokenValue,
	})
}

func getCustomAttestation(tokenRequest customToken) (string, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", *custom_attestation_token_path)
			},
		},
	}

	customJSON, err := json.Marshal(tokenRequest)
	if err != nil {
		glog.Errorf("     Error marshalling custom eat token %v", err)
		return "", err
	}

	glog.V(30).Infof("Posting Custom Token %s\n", string(customJSON))

	url := "http://localhost/v1/token"
	resp, err := httpClient.Post(url, "application/json", strings.NewReader(string(customJSON)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errorResponse, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("Error creating custom token %s", string(errorResponse))
	}
	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(tokenBytes), nil
}

func main() {
	flag.Set("alsologtostderr", "true")
	flag.Set("v", "20")

	flag.Parse()
	var err error
	registry, err = lru.New[string, *common.KeyState](lru_size)
	if err != nil {
		glog.Errorf("Error creating LRU: %v", err)
		os.Exit(1)
	}

	if *useTestIssuer {
		glog.Info("Enabling Test Attestation Token Issuer")
		jwksURL = testJWK
	}
	jwtSet, err = jwk.Fetch(jwksURL)
	if err != nil {
		glog.Errorf("Unable to load JWK Set: %v", err)
		os.Exit(1)
	}

	jwt.MarshalSingleStringAsArray = *marshal_custom_token_string_as_array

	certificate, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		glog.Errorf("could not load server key pair: %s", err)
	}

	clientCACertPool := x509.NewCertPool()
	clientCaCert, err := os.ReadFile(*clientCertCA)
	if err != nil {
		glog.Errorf("could not load TLS Certificate chain: %s", err)
		os.Exit(1)
	}
	clientCACertPool.AppendCertsFromPEM(clientCaCert)

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCACertPool,
	}

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/healthz").HandlerFunc(healthHandler)
	router.Methods(http.MethodPost).Path("/connect").HandlerFunc(connectHandler)
	router.Methods(http.MethodPost).Path("/create_marker").HandlerFunc(createMarkerHandler)
	router.Methods(http.MethodPost).Path("/get_marker").HandlerFunc(getMarkerHandler)
	router.Methods(http.MethodPost).Path("/sign_marker").HandlerFunc(signMarkerHandler)
	router.Methods(http.MethodPost).Path("/get_key").HandlerFunc(getKeyHandler)

	quit := make(chan bool)
	var server *http.Server
	server = &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: &tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		glog.Errorf("Error Starting TLS Server %v\n", err)
		quit <- true
		runtime.Goexit()
	}
	quit <- true
	glog.V(2).Info("Shutting down server")
}
