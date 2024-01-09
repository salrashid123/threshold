package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"

	"math/big"
	"net/http"
	"strings"

	"github.com/golang/glog"

	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	csclaims "github.com/salrashid123/confidential_space/claims"
	"github.com/salrashid123/threshold/generate/common"

	"github.com/hashicorp/vault/sdk/helper/xor"
	"github.com/lestrrat/go-jwx/jwk"
)

const ()

var (
	address = flag.String("host", "localhost:50051", "host:port of gRPC server")

	clientCACert = flag.String("clientCACert", "certs/client-ca.crt", "CACert for client signer")
	clientCAKey  = flag.String("clientCAKey", "certs/client-ca.key", "CAKey for client signer")

	clientCert = flag.String("clientCert", "", "client cert file")

	serverName                           = flag.String("servername", "generate.domain.com", "SNI for server")
	tlsCA                                = flag.String("TLSCACert", "tls-ca-chain.pem", "TLS CA")
	clientCertValidityHours              = flag.Int("clientCertValidityHours", 24, "how long the client cert should be valid for")
	dataToSign                           = flag.String("dataToSign", "fooooo", "Marker Data to sign/verify")
	marker                               = flag.String("marker", "", "marker to use")
	audience                             = flag.String("audience", "some-long-unique-nonce-value", "audience to use")
	mode                                 = flag.String("mode", "", "generate_cert,create_marker,get_marker,add_key,get_key")
	index                                = flag.Int("index", 0, "index of key")
	marker_public_keys                   = flag.String("marker_public_keys", "", "Comma-separated list of all possible Marker Public Keys")
	pubKey                               = flag.String("pubKey", "", "public key to use")
	privKey                              = flag.String("privKey", "", "private key to use")
	cn                                   = flag.String("cn", "participant1", "optional cn value")
	n                                    = flag.Int("n", 3, "n")
	t                                    = flag.Int("t", 2, "t")
	marshal_custom_token_string_as_array = flag.Bool("marshal_custom_token_string_as_array", false, "Try to parse audience and eat_token as string array even if single string")

	allowedImageReference = flag.String("allowedImageReference", "index.docker.io/salrashid123/generate-server@sha256:c7da9ee9a740e648c94e56cb2645897212e3be1815290ac4cf3982e8d77750a1", "Allowed server Image")
	allowedIssuer         = flag.String("allowedIssuer", "https://confidentialcomputing.googleapis.com", "Allowed attestation issuer")
	allowedJWKURL         = flag.String("allowedJWKURL", "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com", "Allowed attestation JWK URL")

	jwtSet *jwk.Set
)

func main() {
	flag.Set("alsologtostderr", "true")
	flag.Set("v", "2")
	flag.Parse()
	if *mode == "generate_cert" {
		if *clientCACert == "" || *clientCAKey == "" || *pubKey == "" || *privKey == "" || *clientCert == "" {
			glog.Errorf("must specify clientCACert,clientCAKey,pubKey,privKey,clientCert")
			os.Exit(1)
		}

		// read the root cert and key that will sign the client cert
		clientCAcrtBytes, err := os.ReadFile(*clientCACert)
		if err != nil {
			glog.Errorf("did not load clientCA certificate: %v", err)
			os.Exit(1)
		}

		block, _ := pem.Decode(clientCAcrtBytes)
		if block == nil {
			glog.Errorf("error reading client ca certificate file %v", err)
			os.Exit(1)
		}
		ccacrt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			glog.Errorf("error parsing client ca certificate  %v", err)
			os.Exit(1)
		}

		clientCAKeyBytes, err := os.ReadFile(*clientCAKey)
		if err != nil {
			glog.Errorf("error reading client ca certificate private key: %v", err)
			os.Exit(1)
		}

		caPrivPem, _ := pem.Decode(clientCAKeyBytes)
		ccakey, err := x509.ParsePKCS8PrivateKey(caPrivPem.Bytes)
		if err != nil {
			glog.Errorf("error decoding client ca certificate ca key %v", err)
			os.Exit(1)
		}

		// now read the participant's private key
		participantPrivateKeyBytes, err := os.ReadFile(*privKey)
		if err != nil {
			glog.Errorf("Error reading participant private key: %v", err)
			os.Exit(1)
		}

		pblock, _ := pem.Decode(participantPrivateKeyBytes)
		if pblock == nil {
			glog.Errorf("error decoding participantKey %v", err)
			os.Exit(1)
		}

		participantParsedKey, err := x509.ParsePKCS8PrivateKey(pblock.Bytes)
		if err != nil {
			glog.Errorf("Error parsing participantPrivateKey %v", err)
			os.Exit(1)
		}

		// issue the CSR
		var csrtemplate = x509.CertificateRequest{
			Subject: pkix.Name{
				Organization:       []string{"Acme Co"},
				OrganizationalUnit: []string{"Enterprise"},
				Locality:           []string{"Mountain View"},
				Province:           []string{"California"},
				Country:            []string{"US"},
				CommonName:         *cn,
			},
			DNSNames: []string{*cn},
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, participantParsedKey)
		if err != nil {
			glog.Errorf("Failed to create CSR: %s", err)
			os.Exit(1)
		}

		csr, err := x509.ParseCertificateRequest(csrBytes)
		if err != nil {
			glog.Errorf("Failed to create CSR: %s", err)
			os.Exit(1)
		}

		//  sign CSR
		var csr_notBefore time.Time
		csr_notBefore = time.Now()
		csr_notAfter := csr_notBefore.Add(time.Hour * time.Duration(*clientCertValidityHours))
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 64)

		csr_serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			glog.Errorf("Failed to generate serial number: %s", err)
			os.Exit(1)
		}

		ccr := &x509.Certificate{
			SerialNumber: csr_serialNumber,
			Subject: pkix.Name{
				Organization:       []string{"Acme Co"},
				OrganizationalUnit: []string{"Enterprise"},
				Locality:           []string{"Mountain View"},
				Province:           []string{"California"},
				Country:            []string{"US"},
				CommonName:         csr.Subject.CommonName,
			},
			NotBefore:             csr_notBefore,
			NotAfter:              csr_notAfter,
			DNSNames:              csr.DNSNames,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}

		cert_c, err := x509.CreateCertificate(rand.Reader, ccr, ccacrt, csr.PublicKey, ccakey)
		if err != nil {
			glog.Errorf("error creating client certificate %v", err)
			os.Exit(1)
		}

		cc, err := x509.ParseCertificate(cert_c)
		if err != nil {
			glog.Errorf("error parsing client certificate %v", err)
			os.Exit(1)
		}

		publicKeyDer, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if err != nil {
			glog.Errorf("error extracting public key as der %v", err)
			os.Exit(1)
		}

		h := sha256.New()
		h.Write(publicKeyDer)
		clientPubKeyHash := base64.StdEncoding.EncodeToString(h.Sum(nil))
		glog.V(2).Infof("Client Public Key Hash %s\n", clientPubKeyHash)

		bc := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cc.Raw,
		}

		certPemBytes := pem.EncodeToMemory(bc)

		// openssl x509 -in certs/0_cert.crt -text -noout
		err = os.WriteFile(*clientCert, certPemBytes, 0644)
		if err != nil {
			glog.Errorf("Error writing PEM client certificate %v", err)
			os.Exit(1)
		}
		glog.V(0).Infof("client certificate written to %s\n", *clientCert)
		return
	}

	if *clientCert == "" || *tlsCA == "" || *privKey == "" || *marker_public_keys == "" {
		glog.Errorf("must specify TLSCACert, clientCert, privKey, marker_public_keys")
		os.Exit(1)
	}
	jwt.MarshalSingleStringAsArray = *marshal_custom_token_string_as_array

	// read the TLS CA
	caCert, err := os.ReadFile(*tlsCA)
	if err != nil {
		glog.Errorf("Error reading tlsCA %v\n", err)
		os.Exit(1)
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)

	// Read the client certificate for this participant
	clientTLSCert, err := tls.LoadX509KeyPair(*clientCert, *privKey)
	if err != nil {
		glog.Errorf("Error reading client certificate and key  %v\n", err)
		os.Exit(1)
	}

	clientCrtBytes, err := os.ReadFile(*clientCert)
	if err != nil {
		glog.Errorf("did not load clientCA certificate: %v\n", err)
		os.Exit(1)
	}

	certBlock, _ := pem.Decode(clientCrtBytes)
	if certBlock == nil {
		glog.Errorf("Error parsing cert block %v\n", err)
		os.Exit(1)
	}
	clientCrt, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		glog.Errorf("Error Parsing client Certificate %v\n", err)
		os.Exit(1)
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(clientCrt.PublicKey)
	if err != nil {
		glog.Errorf("error extracting public key as der %v\n", err)
		os.Exit(1)
	}

	h := sha256.New()
	h.Write(publicKeyDer)
	clientPubKeyHash := hex.EncodeToString(h.Sum(nil))
	glog.V(20).Infof("Client Public Key Hash %s\n", clientPubKeyHash)

	// use the TLSCA, client certs to create a TLS Config
	tlsConfig := &tls.Config{
		ServerName:   *serverName,
		RootCAs:      serverCertPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				c, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				glog.V(20).Infof("Server Subject %s\n", c.Subject)
				//log.Printf("Server Signature %s\n", hex.EncodeToString(c.Signature))
			}
			return nil
		},
	}
	//var ekm []byte
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
		// the following surfaces the EKM on the connection itself (vs on the response TLS)
		// DialTLS: func(network, addr string) (net.Conn, error) {
		// 	conn, err := tls.Dial(network, addr, tlsConfig)
		// 	if err != nil {
		// 		return conn, err
		// 	}
		// 	err = conn.Handshake()
		// 	if err != nil {
		// 		return conn, err
		// 	}
		// 	cs := conn.ConnectionState()

		// 	ekm, err = cs.ExportKeyingMaterial(common.EKMLabel, nil, 32)
		// 	if err != nil {
		// 		return nil, fmt.Errorf("ExportKeyingMaterial failed: %v\n", err)
		// 	}
		// 	glog.V(20).Infof("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

		// 	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		// 	ip := net.ParseIP(host)
		// 	glog.Info("Connected to IP: %s\n", ip)
		// 	return conn, nil
		// },
	}

	client := &http.Client{Transport: tr}

	// now iterate over all the provided participant Keys and XOR it

	xorHash := make([]byte, 32)
	var publicKeysDER [][]byte
	f := strings.Split(*marker_public_keys, ",")
	for _, v := range f {
		pub_key_bytes, err := os.ReadFile(v)
		if err != nil {
			glog.Errorf("     Error reading public key for   %v", err)
			os.Exit(1)
		}

		block, _ := pem.Decode(pub_key_bytes)
		if block == nil {
			glog.Errorf("     Error decoding public key for   %v", err)
			os.Exit(1)
		}

		// p, err := x509.ParsePKIXPublicKey(block.Bytes)
		// if err != nil {
		// 	log.Printf("     Error parsing public key for   %v", err)
		// 	os.Exit(1)
		// }
		// log.Printf("%v", p.(*rsa.PublicKey).N)
		// k := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes})
		// log.Printf("Participant Public Key: \n%s\n", k)

		publicKeysDER = append(publicKeysDER, block.Bytes)

		h := sha256.New()
		h.Write(block.Bytes)
		hsh := h.Sum(nil)
		glog.V(20).Infof("Participant Public Key hashes %s\n", hex.EncodeToString(hsh))
		xorHash, err = xor.XORBytes(xorHash, hsh)
		if err != nil {
			glog.Errorf("     Error hashing public keys fingerprints   %v", err)
			os.Exit(1)
		}
	}

	// first create a connection and verify the ekm and attestation jwt before doing anything real

	glog.V(10).Infof("========================== Connecting /connect ==========================")
	c := common.ConnectRequest{
		Nonce: *audience,
		BaseRequest: common.BaseRequest{
			ParticipantPublicKeys: publicKeysDER,
		},
	}
	connectBody, err := json.Marshal(c)
	if err != nil {
		fmt.Printf("Error marshalling POST JSON %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/connect", *address), "application/json", bytes.NewBuffer(connectBody))
	if err != nil {
		glog.Errorf("Error creating marker: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		connectResponseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			glog.Errorf("Error posting to TEE %v\n", err)
			os.Exit(1)
		}
		err = resp.Body.Close()
		if err != nil {
			glog.Errorf("Error closing body %v\n", err)
			os.Exit(1)
		}
		glog.Errorf("Error getting marker: %v\n", string(connectResponseBody))
		os.Exit(1)
	}

	ekm, err := resp.TLS.ExportKeyingMaterial(common.EKMLabel, nil, 32)
	if err != nil {
		glog.Errorf("ExportKeyingMaterial failed: %v\n", err)
		os.Exit(1)
	}
	glog.V(20).Infof("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

	connectResponseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("Error posting to TEE %v\n", err)
		os.Exit(1)
	}
	err = resp.Body.Close()
	if err != nil {
		glog.Errorf("Error closing body %v\n", err)
		os.Exit(1)
	}
	var cr common.ConnectResponse
	err = json.Unmarshal(connectResponseBody, &cr)
	if err != nil {
		glog.Errorf("Error parsing response from TEE %v\n", err)
		os.Exit(1)
	}

	vt, err := verifyAttestation(cr.AttestationJWT, jwt.WithAudience(clientPubKeyHash), jwt.WithIssuer(*allowedIssuer))
	if err != nil {
		glog.Errorf("error verifying attestation: %v", err)
		os.Exit(1)
	}
	claims, ok := vt.Claims.(*csclaims.Claims)
	if !ok {
		glog.Error("Attestation Token response not valid json struct")
		os.Exit(1)
	}

	if claims.Dbgstat != "disabled-since-boot" {
		glog.Errorf(" disabled-since-boot not set expected disabled-since-boot, got %s:", claims.Dbgstat)
		os.Exit(1)
	}

	// check ekm
	if claims.EATNonce[0] != hex.EncodeToString(ekm) {
		glog.Errorf("EKM Mismatch, expected %s, got %s:", claims.EATNonce[0], hex.EncodeToString(ekm))
		os.Exit(1)
	}
	// check uid of publicKeys
	if claims.EATNonce[1] != cr.Nonce {
		glog.Errorf("Marker mismatch, expected %s, got %s", claims.EATNonce[1], cr.Nonce)
		os.Exit(1)
	}
	// check xor of publicKeys
	if claims.EATNonce[2] != hex.EncodeToString(xorHash) {
		glog.Errorf("Public key hash Mismatch, expected %s, got %s", claims.EATNonce[2], hex.EncodeToString(xorHash))
		os.Exit(1)
	}

	// ************************************
	if *mode == "create_marker" {
		glog.V(10).Info("========================== Create Marker ==========================")
		c := common.CreateMarkerRequest{
			T:          int32(*t),
			N:          int32(*n),
			DataToSign: []byte(*dataToSign),
			BaseRequest: common.BaseRequest{
				ParticipantPublicKeys: publicKeysDER,
			},
		}
		createMarkerBody, err := json.Marshal(c)
		if err != nil {
			glog.Errorf("Error marshalling POST JSON %v\n", err)
			os.Exit(1)
		}

		resp, err := client.Post(fmt.Sprintf("https://%s/create_marker", *address), "application/json", bytes.NewBuffer(createMarkerBody))
		if err != nil {
			glog.Errorf("Error creating marker: %v\n", err)
			os.Exit(1)
		}

		if resp.StatusCode != http.StatusOK {
			getMarkerResponseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				glog.Errorf("Error posting to TEE %v\n", err)
				os.Exit(1)
			}
			err = resp.Body.Close()
			if err != nil {
				glog.Errorf("Error closing body %v\n", err)
				os.Exit(1)
			}

			glog.Errorf("Error getting marker: %v\n", string(getMarkerResponseBody))
			os.Exit(1)
		}

		createMarkerResponseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			glog.Errorf("Error posting to TEE %v\n", err)
			os.Exit(1)
		}
		err = resp.Body.Close()
		if err != nil {
			glog.Errorf("Error closing body %v\n", err)
			os.Exit(1)
		}
		var cr common.CreateMarkerResponse
		err = json.Unmarshal(createMarkerResponseBody, &cr)
		if err != nil {
			glog.Errorf("Error parsing response from TEE %v\n", err)
			os.Exit(1)
		}
		glog.V(10).Infof(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Marker: %s <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n", cr.Uid)

	} else if *mode == "get_marker" {
		glog.V(10).Infof("========================== Get Marker ==========================")
		c := common.GetMarkerRequest{
			Uid:   *marker,
			Nonce: *audience,
			BaseRequest: common.BaseRequest{
				ParticipantPublicKeys: publicKeysDER,
			},
		}
		getMarkerBody, err := json.Marshal(c)
		if err != nil {
			fmt.Printf("Error marshalling POST JSON %v\n", err)
			os.Exit(1)
		}

		resp, err := client.Post(fmt.Sprintf("https://%s/get_marker", *address), "application/json", bytes.NewBuffer(getMarkerBody))
		if err != nil {
			glog.Errorf("Error creating marker: %v\n", err)
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			getMarkerResponseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				glog.Errorf("Error posting to TEE %v\n", err)
				os.Exit(1)
			}
			err = resp.Body.Close()
			if err != nil {
				glog.Errorf("Error closing body %v\n", err)
				os.Exit(1)
			}

			glog.Errorf("Error getting marker: %v\n", string(getMarkerResponseBody))
			os.Exit(1)
		}

		getMarkerResponseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			glog.Errorf("Error posting to TEE %v\n", err)
			os.Exit(1)
		}
		err = resp.Body.Close()
		if err != nil {
			glog.Errorf("Error closing body %v\n", err)
			os.Exit(1)
		}
		var cr common.GetMarkerResponse
		err = json.Unmarshal(getMarkerResponseBody, &cr)
		if err != nil {
			glog.Errorf("Error parsing response from TEE %v\n", err)
			os.Exit(1)
		}

		glog.V(20).Infof("Marker: %s\n", cr.Uid)
		glog.V(20).Infof("T: %d\n", cr.T)
		glog.V(20).Infof("N: %d\n", cr.N)
		glog.V(20).Infof("Quorum: %d\n", cr.Quorum)
		for _, v := range cr.PublicKeyHashes {
			glog.V(20).Infof("    Public key hash; %s\n", v)
		}

		signatureXORHash := make([]byte, 32)
		for _, v := range cr.SignatureSet {
			glog.V(20).Infof("    Signature Public key hash; [%s]\n", hex.EncodeToString(v.ParticipantPublicKey))
			glog.V(20).Infof("    Signature  [%s]\n", base64.StdEncoding.EncodeToString(v.ParticipantSignature))

			h := sha256.New()
			h.Write(v.ParticipantSignature)
			hsh2 := h.Sum(nil)

			signatureXORHash, err = xor.XORBytes(signatureXORHash, hsh2)
			if err != nil {
				glog.Errorf("Error hashing public keys fingerprints %v\n", err)
				os.Exit(1)
			}

			for _, p := range publicKeysDER {
				h := sha256.New()
				h.Write(p)
				hsh := h.Sum(nil)
				if hex.EncodeToString(v.ParticipantPublicKey) == hex.EncodeToString(hsh) {

					k := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p})

					glog.V(20).Infof("KeyHash [%s] of key \n[\n%s\n] found, verifying signature of [%s] locally if Signature value [%s] is present\n", hex.EncodeToString(hsh), k, string(cr.DataToSign), hex.EncodeToString(hsh))
					if len(v.ParticipantSignature) != 0 {
						h := sha256.New()
						h.Write(cr.DataToSign)
						hsh2 := h.Sum(nil)

						publicKey, err := x509.ParsePKIXPublicKey(p)
						if err != nil {
							glog.Errorf("     Error parsing public key for   %v", err)
							os.Exit(1)
						}
						pkey, ok := publicKey.(*rsa.PublicKey)
						if !ok {
							glog.Errorf("Error converting publickey to rsa public key")
							os.Exit(1)
						}
						err = rsa.VerifyPKCS1v15(pkey, crypto.SHA256, hsh2, v.ParticipantSignature)
						if err != nil {
							glog.Errorf("Could not verify marker signature %v", err)
							os.Exit(1)
						}
						glog.V(20).Infof("   Verified marker signature for %s", hex.EncodeToString(hsh))
					}
				}
			}

		}
		glog.V(40).Infof("Signature xor %s\n", hex.EncodeToString(signatureXORHash))

	} else if *mode == "sign_marker" {
		glog.V(20).Infof("========================== Sign Marker ==========================")
		// now read the participant's private key
		participantPrivateKeyBytes, err := os.ReadFile(*privKey)
		if err != nil {
			glog.Errorf("Error reading participant private key: %v", err)
			os.Exit(1)
		}

		pblock, _ := pem.Decode(participantPrivateKeyBytes)
		if pblock == nil {
			glog.Errorf("error decoding participantKey %v", err)
			os.Exit(1)
		}

		participantParsedKey, err := x509.ParsePKCS8PrivateKey(pblock.Bytes)
		if err != nil {
			glog.Errorf("Error parsing participantPrivateKey %v", err)
			os.Exit(1)
		}

		h := sha256.New()
		_, err = h.Write([]byte(*dataToSign))
		if err != nil {
			glog.Errorf("     Error creating signature hash for marker  %v", err)
			os.Exit(1)
		}
		sh := h.Sum(nil)

		pk, ok := participantParsedKey.(*rsa.PrivateKey)
		if !ok {
			glog.Errorf("Error parsing participant public key as RSA key")
			os.Exit(1)
		}
		signature, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, sh)
		if err != nil {
			glog.Errorf("Error signing %v\n", err)
			os.Exit(1)
		}

		c := common.SignMarkerRequest{
			Uid:       *marker,
			Nonce:     *audience,
			Signature: signature,
			BaseRequest: common.BaseRequest{
				ParticipantPublicKeys: publicKeysDER,
			},
		}
		signMarkerBody, err := json.Marshal(c)
		if err != nil {
			fmt.Printf("Error marshalling POST JSON %v\n", err)
			os.Exit(1)
		}

		resp, err := client.Post(fmt.Sprintf("https://%s/sign_marker", *address), "application/json", bytes.NewBuffer(signMarkerBody))
		if err != nil {
			glog.Errorf("Error creating marker: %v\n", err)
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			signMarkerResponseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				glog.Errorf("Error posting to TEE %v\n", err)
				os.Exit(1)
			}
			err = resp.Body.Close()
			if err != nil {
				glog.Errorf("Error closing body %v\n", err)
				os.Exit(1)
			}

			glog.Errorf("Error getting marker: %v\n", string(signMarkerResponseBody))
			os.Exit(1)
		}

		signMarkerResponseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			glog.Errorf("Error posting to TEE %v\n", err)
			os.Exit(1)
		}
		err = resp.Body.Close()
		if err != nil {
			glog.Errorf("Error closing body %v\n", err)
			os.Exit(1)
		}
		var cr common.SignMarkerResponse
		err = json.Unmarshal(signMarkerResponseBody, &cr)
		if err != nil {
			glog.Errorf("Error parsing response from TEE %v\n", err)
			os.Exit(1)
		}

		glog.V(40).Infof("Marker: %s\n", cr.Uid)

	} else if *mode == "get_key" {
		glog.Info("========================== Get Key ==========================")
		// now read the participant's private key
		participantPrivateKeyBytes, err := os.ReadFile(*privKey)
		if err != nil {
			glog.Errorf("Error reading participant private key: %v", err)
			os.Exit(1)
		}

		pblock, _ := pem.Decode(participantPrivateKeyBytes)
		if pblock == nil {
			glog.Errorf("error decoding participantKey %v", err)
			os.Exit(1)
		}

		participantParsedKey, err := x509.ParsePKCS8PrivateKey(pblock.Bytes)
		if err != nil {
			glog.Errorf("Error parsing participantPrivateKey %v", err)
			os.Exit(1)
		}

		c := common.GetKeyRequest{
			Uid:   *marker,
			Nonce: *audience,
			BaseRequest: common.BaseRequest{
				ParticipantPublicKeys: publicKeysDER,
			},
		}
		signMarkerBody, err := json.Marshal(c)
		if err != nil {
			fmt.Printf("Error marshalling POST JSON %v\n", err)
			os.Exit(1)
		}

		resp, err := client.Post(fmt.Sprintf("https://%s/get_key", *address), "application/json", bytes.NewBuffer(signMarkerBody))
		if err != nil {
			glog.Errorf("Error creating marker: %v\n", err)
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			signMarkerResponseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				glog.Errorf("Error posting to TEE %v\n", err)
				os.Exit(1)
			}
			err = resp.Body.Close()
			if err != nil {
				glog.Errorf("Error closing body %v\n", err)
				os.Exit(1)
			}

			glog.V(20).Infof("Error getting marker: %v\n", string(signMarkerResponseBody))
			os.Exit(1)
		}

		getKeyResponseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			glog.Errorf("Error posting to TEE %v\n", err)
			os.Exit(1)
		}
		err = resp.Body.Close()
		if err != nil {
			glog.Errorf("Error closing body %v\n", err)
			os.Exit(1)
		}
		var cr common.GetKeyResponse
		err = json.Unmarshal(getKeyResponseBody, &cr)
		if err != nil {
			glog.Errorf("Error parsing response from TEE %v\n", err)
			os.Exit(1)
		}

		glog.V(10).Infof("Marker: %s\n", cr.Uid)
		glog.V(10).Infof("ThresholdPublic: %s\n", base64.StdEncoding.EncodeToString(cr.ThresholdPublic))
		glog.V(10).Infof("Index: %d\n", cr.Index)
		glog.V(10).Infof("SharePublic: %s\n", base64.StdEncoding.EncodeToString(cr.SharePublic))
		glog.V(40).Infof("EncryptedSharePrivate: %s\n", base64.StdEncoding.EncodeToString(cr.EncryptedSharePrivate))
		hash := sha256.New()
		plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, participantParsedKey.(*rsa.PrivateKey), cr.EncryptedSharePrivate, []byte(*marker))
		if err != nil {
			glog.Errorf("     Error decrypting with private key %v", err)
			os.Exit(1)
		}

		glog.V(10).Infof("Decrypted private key share  %s\n", base64.StdEncoding.EncodeToString(plaintext))
	} else {
		glog.Errorf("mode must be one of create_marker, get_marker, sign_marker, get_key")
		os.Exit(1)
	}

}

func verifyAttestation(attestation string, opts ...jwt.ParserOption) (*jwt.Token, error) {
	glog.V(20).Infof("Verifying Confidential Space Attestation Token")

	var err error
	if jwtSet == nil {
		jwtSet, err = jwk.Fetch(*allowedJWKURL)
		if err != nil {
			return nil, err
		}
	}

	gcpIdentityDoc := &csclaims.Claims{}

	token, err := jwt.ParseWithClaims(string(attestation), gcpIdentityDoc, func(token *jwt.Token) (interface{}, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}
		if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
			return key[0].Materialize()
		}
		return nil, errors.New("unable to find key")
	}, opts...)
	if err != nil {
		glog.Errorf("     Error validating Confidential Space Attestation Token signature %v", err)
		return nil, err
	}
	glog.V(40).Infof("Confidential Space Attestation signature verified")
	if claims, ok := token.Claims.(*csclaims.Claims); ok && token.Valid {
		glog.V(20).Infof("Claims in Confidential Space Attestation Token:")
		// printedClaims, err := json.MarshalIndent(claims, "", "  ")
		// if err != nil {
		// 	log.Printf(err.Error())
		// 	return nil, err
		// }
		// log.Printf("%s\n", string(printedClaims))
		glog.V(20).Infof("  Image Hash  %s\n", claims.Submods.Container.ImageReference)
		glog.V(20).Infof("  ProjectID  %s\n", claims.Submods.GCE.ProjectID)
		glog.V(20).Infof("  EAT Nonce for index  %s\n", claims.EATNonce)

		if claims.Submods.Container.ImageReference != *allowedImageReference {
			return nil, fmt.Errorf("Invalid image reference, expected %s  got %s", *allowedImageReference, claims.Submods.Container.ImageReference)
		}

		// also check debug status, SEV status

	} else {
		glog.Errorf("error unmarshalling jwt token %v\n", err)
		return nil, err
	}
	return token, nil
}
