package common

const EKMLabel = "my_nonce"

type BaseRequest struct {
	ParticipantPublicKeys [][]byte `json:"participant_public_keys"`
}

type ConnectRequest struct {
	Nonce string `json:"nonce"`
	BaseRequest
}

type ConnectResponse struct {
	Nonce          string `json:"nonce"`
	AttestationJWT string `json:"attestation_jwt"`
}

type CreateMarkerRequest struct {
	T          int32  `json:"t"`
	N          int32  `json:"n"`
	DataToSign []byte `json:"data_to_sign"`
	BaseRequest
}

type CreateMarkerResponse struct {
	Uid            string `json:"uid"`
	AttestationJWT string `json:"attestation_jwt"`
}

type GetMarkerRequest struct {
	Uid   string `json:"uid"`
	Nonce string `json:"nonce"`
	BaseRequest
}

type SignatureSet struct {
	ParticipantPublicKey []byte `json:"participant_public_key"`
	ParticipantSignature []byte `json:"participant_signature"`
}

type GetMarkerResponse struct {
	Uid             string         `json:"uid"`
	PublicKeyHashes []string       `json:"public_key_hashes"`
	SignatureSet    []SignatureSet `json:"signature_set"`
	T               int32          `json:"t"`
	N               int32          `json:"n"`
	Quorum          int32          `json:"quorum"`
	DataToSign      []byte         `json:"data_to_sign"`
	AttestationJWT  string         `json:"attestation_jwt"`
}

type SignMarkerRequest struct {
	Uid       string `json:"uid"`
	Nonce     string `json:"nonce"`
	Signature []byte `json:"signature"`
	BaseRequest
}

type SignMarkerResponse struct {
	Uid            string `json:"uid"`
	AttestationJWT string `json:"attestation_jwt"`
}

type GetKeyRequest struct {
	Uid   string `json:"uid"`
	Nonce string `json:"nonce"`
	BaseRequest
}

type GetKeyResponse struct {
	Uid                   string `json:"uid"`
	Index                 int    `json:"index"`
	ThresholdPublic       []byte `json:"threshold_public"`
	SharePublic           []byte `json:"share_public"`
	EncryptedSharePrivate []byte `json:"encrypted_share_private"`
	AttestationJWT        string `json:"attestation_jwt"`
}
