package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/golang/glog"

	"os"

	"github.com/golang-jwt/jwt/v5"

	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/sign/tbls"

	csclaims "github.com/salrashid123/confidential_space/claims"
	"github.com/salrashid123/threshold/sign/common"

	"github.com/lestrrat/go-jwx/jwk"
)

/*
export PUBLIC_KEY=SKwCfvuwyRPxvxcU/+1rpKq9asTyUWq3UUYOC74oys4HOdl+m+Uof7XYPyslyX+J7i6lkcyAXENK8VZBh6adwDoWKvHTrkXsVK9O7IOyY69gF/sWzyK0uz3RaQOfcexeQJAX13z5TApxUEuHuIs7eB++NaX1eiJACUxZosnKRZ0=

export SPU_0=c5M81sPtGl9Otea0TFx/G5a6wgh/it7+6wqspoLsg/MxEDX5t9a96NLQomggRuQ18ntpCYR7atvxUqg4qdUoAHOJF8STj916RSS5hHfSHydjVnWWXY9p3HenT8yPH45YWLfTQLEyEp+r0zgNjd0QynoZbT4DcZl5UD2za0PPGD0=
export SPU_1=HAbWgWbVvn6nUqOENe9rtXvXVK6zpLzssML8N/vTuTMwujPQ2mC5+lDO2QfbW3QbESuWzGd5aYHmrRYS+pk6sn/GSkt3T7zf0JfS7PXSk4Kt4dbix0nzff0fSSJmiYnHHd0Fhs+2omRR/k/vRjz/oRY5FX5RiY2az4BerHSOalY=
export SPU_2=QuQuaJ4uIAHx6CeAzbUisnwoH8zA1dNoTVgwmPnv/ex2juXZO0Vt/2wtnOSgopZ2In6dw1X+23oSevPQ6A/bs2O7E/73aTS5xwUaEqM8nQZRZFfZjsBkXUyUHUjdqihYJueHBVLsnqUxqvYBSz7iZXxYQv/C6fOrLcy/GQs0l0A=
export SPR_0=c7adJDYwiSC4zGyE3EGd0ZAhb9xufg98b5wwdNK++Gc=
export SPR_1=C/bIqUQGkiwE9zznChELj8vAwhfLORgOENW4KKoxuS8=
export SPR_2=M+v2EZyAIzD7kfoBmWVVbzXtomYgHd1nDzD40N9lQ7Fg=
*/
const ()

var (
	address = flag.String("host", "localhost:8081", "host:port of gRPC server")

	serverName = flag.String("servername", "sign.domain.com", "SNI for server")
	tlsCA      = flag.String("TLSCACert", "certs/tls-ca-chain.pem", "TLS CA")

	sharePublicKey                       = flag.String("sharePublicKey", "SKwCfvuwyRPxvxcU/+1rpKq9asTyUWq3UUYOC74oys4HOdl+m+Uof7XYPyslyX+J7i6lkcyAXENK8VZBh6adwDoWKvHTrkXsVK9O7IOyY69gF/sWzyK0uz3RaQOfcexeQJAX13z5TApxUEuHuIs7eB++NaX1eiJACUxZosnKRZ0=", "Threshold Public key")
	dataToSign                           = flag.String("dataToSign", "fooooo", "Marker Data to sign/verify")
	marker                               = flag.String("marker", "", "marker to use")
	audience                             = flag.String("audience", "http://foo.bar", "audience to use")
	mode                                 = flag.String("mode", "", "")
	nonce                                = flag.String("nonce", "some-random-nonce-value", "Nonce Value")
	index                                = flag.Int("index", 0, "index of key")
	pubKey                               = flag.String("share_public_key", "", "public key to use")
	privKey                              = flag.String("share_private_key", "", "private key to use")
	n                                    = flag.Int("n", 3, "n")
	t                                    = flag.Int("t", 2, "t")
	marshal_custom_token_string_as_array = flag.Bool("marshal_custom_token_string_as_array", false, "Try to parse audience and eat_token as string array even if single string")

	allowedImageReference = flag.String("allowedImageReference", "index.docker.io/salrashid123/sign-server@sha256:f00385461318c10f19a37856597eaecc3bbd33cad3aafe05e2c14e48096a87d8", "Allowed server Image")
	allowedIssuer         = flag.String("allowedIssuer", "https://confidentialcomputing.googleapis.com", "Allowed attestation issuer")
	allowedJWKURL         = flag.String("allowedJWKURL", "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com", "Allowed attestation JWK URL")

	//jwksURL = fmt.Sprintf("file://%s", *certPrefix+"jwk.json")
	jwtSet *jwk.Set
)

func main() {
	flag.Set("alsologtostderr", "true")
	flag.Set("v", "2")

	flag.Parse()

	if *tlsCA == "" {
		glog.Errorf("must specify TLSCACer")
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

	// use the TLSCA, client certs to create a TLS Config
	tlsConfig := &tls.Config{
		ServerName: *serverName,
		RootCAs:    serverCertPool,
		MinVersion: tls.VersionTLS13,
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
		// 	glog.V(20).Infof"EKM my_nonce: %s\n", hex.EncodeToString(ekm))

		// 	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		// 	ip := net.ParseIP(host)
		// 	glog.V(20).Infof("Connected to IP: %s\n", ip)
		// 	return conn, nil
		// },
	}

	client := &http.Client{Transport: tr}

	// first create a connection and verify the ekm and attestation jwt before doing anything real

	glog.V(10).Info("========================== Connecting /connect ==========================")
	c := common.ConnectRequest{
		Nonce: *nonce,
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

	vt, err := verifyAttestation(cr.AttestationJWT, jwt.WithAudience(*nonce), jwt.WithIssuer(*allowedIssuer))
	if err != nil {
		glog.Errorf("error verifying attestation: %v", err)
		os.Exit(1)
	}

	claims, ok := vt.Claims.(*csclaims.Claims)
	if !ok {
		glog.Error("Attestation Token response not valid json struct")
		os.Exit(1)
	}

	// check ekm
	if claims.EATNonce[0] != hex.EncodeToString(ekm) {
		glog.Errorf("EKM Mismatch, expected %s, got %s:", claims.EATNonce[0], hex.EncodeToString(ekm))
		os.Exit(1)
	}
	// // check uid of publicKeys
	// if claims.EATNonce[1] != cr.Nonce {
	// 	glog.Errorf("Marker mismatch, expected %s, got %s", claims.EATNonce[1], cr.Nonce)
	// 	os.Exit(1)
	// }
	// // check xor of publicKeys
	// if claims.EATNonce[2] != hex.EncodeToString(xorHash) {
	// 	glog.Errorf("Public key hash Mismatch, expected %s, got %s", claims.EATNonce[2], hex.EncodeToString(xorHash))
	// 	os.Exit(1)
	// }

	// ************************************
	if *mode == "create_marker" {
		glog.V(10).Infof("========================== Create Marker ==========================")

		h := sha256.New()
		h.Write([]byte(*dataToSign))
		dhsh := h.Sum(nil)

		c := common.CreateMarkerRequest{
			Nonce:          *nonce,
			T:              *t,
			N:              *n,
			DataToSign:     base64.StdEncoding.EncodeToString(dhsh),
			SharePublicKey: *sharePublicKey,
		}
		createMarkerBody, err := json.Marshal(c)
		if err != nil {
			fmt.Printf("Error marshalling POST JSON %v\n", err)
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
		glog.V(2).Infof(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Marker: %s <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n", cr.Uid)

		t, err := verifyAttestation(cr.AttestationJWT, jwt.WithAudience(*nonce), jwt.WithIssuer(*allowedIssuer))
		if err != nil {
			glog.Errorf("error verifying attestation: %v", err)
			os.Exit(1)
		}
		//glog.Errorf("Verifed %s\n", t.Raw)
		claims, ok := t.Claims.(*csclaims.Claims)
		if !ok {
			glog.Error("Attestation Token response not valid json struct")
			os.Exit(1)
		}

		p, err := base64.StdEncoding.DecodeString(*sharePublicKey)
		if err != nil {
			glog.Errorf("error verifying attestation: %v", err)
			os.Exit(1)
		}
		h2 := sha256.New()
		h2.Write(p)
		pkhsh := h2.Sum(nil)

		// check ekm
		if claims.EATNonce[0] != hex.EncodeToString(ekm) {
			glog.Errorf("EKM Mismatch, expected %s, got %s:", claims.EATNonce[0], hex.EncodeToString(ekm))
			os.Exit(1)
		}
		// check uid of publicKeys
		if claims.EATNonce[1] != cr.Uid {
			glog.Errorf("Marker mismatch, expected %s, got %s", claims.EATNonce[1], cr.Uid)
			os.Exit(1)
		}

		if claims.EATNonce[2] != base64.StdEncoding.EncodeToString(pkhsh) {
			glog.Errorf("Public Key, expected %s, got %s", claims.EATNonce[2], base64.StdEncoding.EncodeToString(pkhsh))
			os.Exit(1)
		}

		if claims.EATNonce[3] != base64.StdEncoding.EncodeToString(dhsh) {
			glog.Errorf("DataToSign mismatch, expected %s, got %s", claims.EATNonce[3], base64.StdEncoding.EncodeToString(dhsh))
			os.Exit(1)
		}

	} else if *mode == "get_marker" {
		glog.V(10).Infof("========================== Get Marker ==========================")

		h := sha256.New()
		h.Write([]byte(*dataToSign))
		dhsh := h.Sum(nil)

		p, err := base64.StdEncoding.DecodeString(*sharePublicKey)
		if err != nil {
			glog.Errorf("     Error decoding share public key %v", err)
			os.Exit(1)
		}

		h2 := sha256.New()
		h2.Write(p)
		puhsh := h2.Sum(nil)

		c := common.GetMarkerRequest{
			Uid:   *marker,
			Nonce: *nonce,
		}
		createMarkerBody, err := json.Marshal(c)
		if err != nil {
			fmt.Printf("Error marshalling POST JSON %v\n", err)
			os.Exit(1)
		}

		resp, err := client.Post(fmt.Sprintf("https://%s/get_marker", *address), "application/json", bytes.NewBuffer(createMarkerBody))
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

		t, err := verifyAttestation(cr.AttestationJWT, jwt.WithAudience(*nonce), jwt.WithIssuer(*allowedIssuer))
		if err != nil {
			glog.Errorf("error verifying attestation: %v", err)
			os.Exit(1)
		}
		//glog.Errorf("Verifed %s\n", t.Raw)
		claims, ok := t.Claims.(*csclaims.Claims)
		if !ok {
			glog.Error("Attestation Token response not valid json struct")
			os.Exit(1)
		}

		// check ekm
		if claims.EATNonce[0] != hex.EncodeToString(ekm) {
			glog.Errorf("EKM Mismatch, expected %s, got %s:", claims.EATNonce[0], hex.EncodeToString(ekm))
			os.Exit(1)
		}
		// check uid of publicKeys
		if claims.EATNonce[1] != *marker {
			glog.Errorf("Marker mismatch, expected %s, got %s", claims.EATNonce[1], *marker)
			os.Exit(1)
		}
		if claims.EATNonce[2] != *nonce {
			glog.Errorf("Nonce mismatch, expected %s, got %s", claims.EATNonce[2], *nonce)
			os.Exit(1)
		}

		if claims.EATNonce[3] != base64.StdEncoding.EncodeToString(puhsh) {
			glog.Errorf("PublicKey hash mismatch, expected %s, got %s", claims.EATNonce[3], base64.StdEncoding.EncodeToString(puhsh))
			os.Exit(1)
		}

		if claims.EATNonce[4] != base64.StdEncoding.EncodeToString(dhsh) {
			glog.Errorf("DataToSign mismatch, expected %s, got %s", claims.EATNonce[4], base64.StdEncoding.EncodeToString(dhsh))
			os.Exit(1)
		}

		if claims.EATNonce[5] != "" {
			ds, err := base64.StdEncoding.DecodeString(cr.Signature)
			if err != nil {
				glog.Errorf("Error decoding signature hash %v\n", err)
				os.Exit(1)
			}
			sh := sha256.New()
			sh.Write(ds)
			shhash := sh.Sum(nil)
			if claims.EATNonce[5] != base64.StdEncoding.EncodeToString(shhash) {
				glog.Errorf("Signature hash  mismatch, expected %s, got %s", claims.EATNonce[5], base64.StdEncoding.EncodeToString(shhash))
				os.Exit(1)
			}
		}

		dst := &bytes.Buffer{}
		if err := json.Indent(dst, getMarkerResponseBody, "", "  "); err != nil {
			glog.Errorf("Error parsing response %v\n", err)
			os.Exit(1)
		}

		glog.V(40).Infof("Response: %s\n", dst.String())
		glog.V(20).Infof("Share Public Key: %s", cr.SharePublicKey)
		glog.V(20).Infof("Signature : %s", cr.Signature)

	} else if *mode == "add_signature" {
		glog.V(20).Info("========================== Add Signature ==========================")

		h := sha256.New()
		h.Write([]byte(*dataToSign))
		dhsh := h.Sum(nil)

		suite := bn256.NewSuite()
		rv := suite.G2().Scalar()
		pval, err := base64.StdEncoding.DecodeString(*privKey)
		if err != nil {
			glog.Errorf("Error decoding private key %v\n", err)
			os.Exit(1)
		}
		err = rv.UnmarshalBinary(pval)
		if err != nil {
			glog.Errorf("Error unmarshalling private threshold key %v\n", err)
			os.Exit(1)
		}
		rr := &share.PriShare{
			I: *index,
			V: rv,
		}

		sig, err := tbls.Sign(suite, rr, dhsh)
		if err != nil {
			glog.Errorf("DataToSign mismatch, expected %s, got %s", claims.EATNonce[3], base64.StdEncoding.EncodeToString(dhsh))
			os.Exit(1)
		}
		glog.V(20).Infof("Private Share %d: %s\n", *index, rr.V.String())
		glog.V(20).Infof("Share Signature %d: %s\n", *index, base64.StdEncoding.EncodeToString(sig))

		c := common.AddSignatureRequest{
			Index:          *index,
			Public:         *pubKey,
			SignatureShare: base64.StdEncoding.EncodeToString(sig),
			Uid:            *marker,
			Nonce:          *nonce,
		}
		createMarkerBody, err := json.Marshal(c)
		if err != nil {
			fmt.Printf("Error marshalling POST JSON %v\n", err)
			os.Exit(1)
		}

		resp, err := client.Post(fmt.Sprintf("https://%s/add_signature", *address), "application/json", bytes.NewBuffer(createMarkerBody))
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

		addSignatureResponseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			glog.Errorf("Error posting to TEE %v\n", err)
			os.Exit(1)
		}
		err = resp.Body.Close()
		if err != nil {
			glog.Errorf("Error closing body %v\n", err)
			os.Exit(1)
		}
		var cr common.AddSignatureResponse
		err = json.Unmarshal(addSignatureResponseBody, &cr)
		if err != nil {
			glog.Errorf("Error parsing response from TEE %v\n", err)
			os.Exit(1)
		}

		t, err := verifyAttestation(cr.AttestationJWT, jwt.WithAudience(*nonce), jwt.WithIssuer(*allowedIssuer))
		if err != nil {
			glog.Errorf("error verifying attestation: %v", err)
			os.Exit(1)
		}
		//log.Printf("Verifed %s\n", t.Raw)
		claims, ok := t.Claims.(*csclaims.Claims)
		if !ok {
			glog.Error("Attestation Token response not valid json struct")
			os.Exit(1)
		}
		glog.V(20).Infof("Quorum %d", cr.Quorum)

		// check ekm
		if claims.EATNonce[0] != hex.EncodeToString(ekm) {
			glog.Errorf("EKM Mismatch, expected %s, got %s:", claims.EATNonce[0], hex.EncodeToString(ekm))
			os.Exit(1)
		}
		// check uid of publicKeys
		if claims.EATNonce[1] != *marker {
			glog.Errorf("Marker mismatch, expected %s, got %s", claims.EATNonce[1], *marker)
			os.Exit(1)
		}
		if claims.EATNonce[2] != *nonce {
			glog.Errorf("Nonce mismatch, expected %s, got %s", claims.EATNonce[2], *nonce)
			os.Exit(1)
		}

	}
	// ************************************

}

func verifyAttestation(attestation string, opts ...jwt.ParserOption) (*jwt.Token, error) {
	glog.V(40).Infof("Verifying Confidential Space Attestation Token")

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
		glog.V(40).Infof("Claims in Confidential Space Attestation Token:")
		// printedClaims, err := json.MarshalIndent(claims, "", "  ")
		// if err != nil {
		// 	log.Printf(err.Error())
		// 	return nil, err
		// }
		// log.Printf("%s\n", string(printedClaims))
		glog.V(40).Infof("  Image Hash  %s\n", claims.Submods.Container.ImageReference)
		glog.V(40).Infof("  ProjectID  %s\n", claims.Submods.GCE.ProjectID)
		glog.V(40).Infof("  EAT Nonce for index  %s\n", claims.EATNonce)

		if claims.Submods.Container.ImageReference != *allowedImageReference {
			return nil, fmt.Errorf("Invalid image reference, expected %s  got %s", allowedImageReference, claims.Submods.Container.ImageReference)
		}

		// also check debug status, SEV status

	} else {
		glog.Errorf("error unmarshalling jwt token %v\n", err)
		return nil, err
	}
	return token, nil
}
