package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/lestrrat/go-jwx/jwk"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/sign/bdn"
	"go.dedis.ch/kyber/v4/sign/tbls"

	"github.com/golang-jwt/jwt/v5"

	tk "github.com/salrashid123/confidential_space/misc/testtoken"
	"github.com/salrashid123/threshold/sign/common"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
)

const (
	lru_size = 200
)

var (
	listen = flag.String("listen", ":8081", "address to listen on (default :8081)")

	jwksURL       = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	useTestIssuer = flag.Bool("useTestIssuer", false, "Use Testing attestation token Issuer")

	tlsCert                              = flag.String("tlsCert", "certs/server.crt", "TLS Cert")
	tlsKey                               = flag.String("tlsKey", "certs/server.key", "TLS Key")
	tlsCA                                = flag.String("tlsCA", "certs/tls-ca-chain.pem", "TLS CA")
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
	EKM string
}

type server struct{}

type contextKey string

const contextEventKey contextKey = "event"

func eventsMiddleware(h http.Handler) http.Handler {
	glog.Infoln("--------------------------------")
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

		ekm, err := r.TLS.ExportKeyingMaterial(common.EKMLabel, nil, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		glog.V(20).Infof("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

		event := &event{
			EKM: hex.EncodeToString(ekm),
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

	glog.Info("Got Connect request")

	var post common.ConnectRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  post.Nonce,
			Nonces:    []string{val.EKM},
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  post.Nonce,
			Nonces:    []string{val.EKM},
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
	val := r.Context().Value(contextKey("event")).(event)

	glog.V(20).Info("Got CreateMarker request")

	var post common.CreateMarkerRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// now update the 'database' with the marker specifications

	id := uuid.New()
	uid := id.String()

	mu.Lock()
	defer mu.Unlock()

	var ks []*common.KeyShare
	// ks := make([]common.KeyShare, post.N)
	// registry[uid] = common.KeyState{
	// T:          post.T,
	// N:          post.N,
	// Marker:     uid,
	// SharePublicKey: post.SharePublicKey,
	// KeyShares:  ks,
	// DataToSign: post.DataToSign,
	// Quorum:     0,
	// }
	registry.Add(uid, &common.KeyState{
		T:              post.T,
		N:              post.N,
		Marker:         uid,
		SharePublicKey: post.SharePublicKey,
		KeyShares:      ks,
		DataToSign:     post.DataToSign,
		Quorum:         0,
	})

	p, err := base64.StdEncoding.DecodeString(post.SharePublicKey)
	if err != nil {
		glog.Errorf("     Error decoding share public key %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h := sha256.New()
	h.Write(p)
	pkhsh := h.Sum(nil)

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  post.Nonce,
			Nonces:    []string{val.EKM, uid, base64.StdEncoding.EncodeToString(pkhsh), post.DataToSign},
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  post.Nonce,
			Nonces:    []string{val.EKM, uid, base64.StdEncoding.EncodeToString(pkhsh), post.DataToSign},
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
	json.NewEncoder(w).Encode(&common.CreateMarkerResponse{
		Uid:            uid,
		AttestationJWT: customTokenValue,
	})
}

func getMarkerHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	val := r.Context().Value(contextKey("event")).(event)

	glog.Info("Got GetMarker request")

	var post common.GetMarkerRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	e, ok := registry.Get(post.Uid)
	//e, ok := registry[post.Uid]
	if !ok {
		glog.Errorf("UID not registered")
		http.Error(w, fmt.Sprintf("UID not registered"), http.StatusBadRequest)
		return
	}

	p, err := base64.StdEncoding.DecodeString(e.SharePublicKey)
	if err != nil {
		glog.Errorf("     Error decoding share public key %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h := sha256.New()
	h.Write(p)
	puhsh := h.Sum(nil)

	s, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		glog.Errorf("     Error decoding share public key %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h2 := sha256.New()
	h2.Write(s)
	sigsh := h2.Sum(nil)

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  post.Nonce,
			Nonces:    []string{val.EKM, post.Uid, post.Nonce, base64.StdEncoding.EncodeToString(puhsh), e.DataToSign, base64.StdEncoding.EncodeToString(sigsh)},
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  post.Nonce,
			Nonces:    []string{val.EKM, post.Uid, post.Nonce, base64.StdEncoding.EncodeToString(puhsh), e.DataToSign, base64.StdEncoding.EncodeToString(sigsh)},
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
	json.NewEncoder(w).Encode(&common.GetMarkerResponse{
		T:              e.T,
		N:              e.N,
		Quorum:         e.Quorum,
		SharePublicKey: e.SharePublicKey,
		DataToSign:     e.DataToSign,
		Signature:      e.Signature,
		AttestationJWT: customTokenValue,
	})
}

func addSignatureHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	val := r.Context().Value(contextKey("event")).(event)

	glog.V(20).Info("Got SignMarker request")

	var post common.AddSignatureRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		glog.Errorf("Error parsing POST data %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	e, ok := registry.Get(post.Uid)
	//e, ok := registry[post.Uid]
	if !ok {
		glog.Errorf("UID not registered")
		http.Error(w, fmt.Sprintf("UID not registered"), http.StatusBadRequest)
		return
	}

	for _, k := range e.KeyShares {
		if k.Index == post.Index {
			glog.Errorf("Signature for keyIndex already submitted")
			http.Error(w, fmt.Sprintf("Signature already submitted"), http.StatusBadRequest)
			return
		}
	}

	e.KeyShares = append(e.KeyShares, &common.KeyShare{
		Index:       post.Index,
		SharePublic: post.Public,
		Signature:   post.SignatureShare,
	})
	e.Quorum++

	if e.Quorum == e.T {
		glog.V(20).Infof("Threshold Reached for marker %s\n", e.Marker)
		suite := bn256.NewSuite()
		pp := []*share.PubShare{}
		sigShares := make([][]byte, 0)

		for _, s := range e.KeyShares {
			rv := suite.G2().Point()

			binpublic, err := base64.StdEncoding.DecodeString(s.SharePublic)
			if err != nil {
				glog.Errorf("Error decoding share Public %v\n", err)
				http.Error(w, fmt.Sprintf("Error decoding share Public %v\n", err), http.StatusBadRequest)
				return
			}
			err = rv.UnmarshalBinary(binpublic)
			if err != nil {
				glog.Errorf("Error unmarshalling share Public %v\n", err)
				http.Error(w, fmt.Sprintf("Error unmarshalling share Public %v\n", err), http.StatusBadRequest)
				return
			}

			rr := &share.PubShare{
				I: s.Index,
				V: rv,
			}
			pp = append(pp, rr)
			sigbytes, err := base64.StdEncoding.DecodeString(s.Signature)
			if err != nil {
				glog.Errorf("Error decoding signature %v\n", err)
				http.Error(w, fmt.Sprintf("Error decoding signature  %v\n", err), http.StatusBadRequest)
				return
			}
			sigShares = append(sigShares, sigbytes)
		}
		recoveredpubPolyReovered, err := share.RecoverPubPoly(suite.G2(), pp, e.T, e.N)
		if err != nil {
			glog.Errorf("Error recovering public polynominal %v\n", err)
			http.Error(w, fmt.Sprintf("Error recovering public polynominal  %v\n", err), http.StatusBadRequest)
			return
		}

		databytes, err := base64.StdEncoding.DecodeString(e.DataToSign)
		if err != nil {
			glog.Errorf("Error decopding data to sign %v\n", err)
			http.Error(w, fmt.Sprintf("Error decopding data to sign %v\n", err), http.StatusBadRequest)
			return
		}
		sig, err := tbls.Recover(suite, recoveredpubPolyReovered, databytes, sigShares, e.T, e.N)
		if err != nil {
			glog.Errorf("Error recovering signature  %v\n", err)
			http.Error(w, fmt.Sprintf("Error recovering signature  %v\n", err), http.StatusBadRequest)
			return
		}
		err = bdn.Verify(suite, recoveredpubPolyReovered.Commit(), databytes, sig)
		if err != nil {
			glog.Errorf("Error verifying signature %v\n", err)
			http.Error(w, fmt.Sprintf("Error verifying signature  %v\n", err), http.StatusBadRequest)
			return
		}
		e.Signature = base64.StdEncoding.EncodeToString(sig)
	}

	eat_nonce := []string{val.EKM, post.Uid, post.Nonce}
	var signatureHash string
	if e.Signature != "" {
		sigbytes, err := base64.StdEncoding.DecodeString(e.Signature)
		if err != nil {
			glog.Errorf("     Error decodign provided signature %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h := sha256.New()
		h.Write(sigbytes)
		signatureHash = base64.StdEncoding.EncodeToString(h.Sum(nil))
		eat_nonce = append(eat_nonce, signatureHash)
	}

	var customTokenValue string
	if *useTestIssuer {
		// for test token
		customTokenValue, err = tk.GetCustomAttestation(&tk.CustomToken{
			Audience:  post.Nonce,
			Nonces:    eat_nonce,
			TokenType: TOKEN_TYPE_OIDC,
		})
	} else {
		// // for actual confidential space
		ttsa := customToken{
			Audience:  post.Nonce,
			Nonces:    eat_nonce,
			TokenType: TOKEN_TYPE_OIDC,
		}
		customTokenValue, err = getCustomAttestation(ttsa)
	}
	if err != nil {
		glog.Errorf("     Error creating Custom JWT %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//registry[post.Uid] = e
	registry.Add(post.Uid, e)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&common.AddSignatureResponse{
		T:              e.T,
		N:              e.N,
		Quorum:         e.Quorum,
		AttestationJWT: customTokenValue,
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

	glog.V(2).Infof("Posting Custom Token %s\n", string(customJSON))

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
	flag.Set("v", "2")
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

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/healthz").HandlerFunc(healthHandler)
	router.Methods(http.MethodPost).Path("/connect").HandlerFunc(connectHandler)
	router.Methods(http.MethodPost).Path("/create_marker").HandlerFunc(createMarkerHandler)
	router.Methods(http.MethodPost).Path("/get_marker").HandlerFunc(getMarkerHandler)
	router.Methods(http.MethodPost).Path("/add_signature").HandlerFunc(addSignatureHandler)

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
	glog.Info("Shutting down server")
}
