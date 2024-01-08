package common

const EKMLabel = "my_nonce"

type ConnectRequest struct {
	Nonce string `json:"nonce"`
}

type ConnectResponse struct {
	Nonce          string `json:"nonce"`
	AttestationJWT string `json:"attestation_jwt"`
}

type CreateMarkerRequest struct {
	Nonce          string `json:"nonce"`
	T              int    `json:"t"`
	N              int    `json:"n"`
	SharePublicKey string `json:"share_public_key"`
	DataToSign     string `json:"data_to_sign"`
}

type CreateMarkerResponse struct {
	Uid            string `json:"uid"`
	AttestationJWT string `json:"attestation_jwt"`
}

type GetMarkerRequest struct {
	Uid   string `json:"uid"`
	Nonce string `json:"nonce"`
}

type GetMarkerResponse struct {
	T              int    `json:"t"`
	N              int    `json:"n"`
	Quorum         int    `json:"quorum"`
	SharePublicKey string `json:"share_public_key"`
	DataToSign     string `json:"data_to_sign"`
	Signature      string `json:"signature"`
	AttestationJWT string `json:"attestation_jwt"`
}

type AddSignatureRequest struct {
	Uid            string `json:"uid"`
	Nonce          string `json:"nonce"`
	Index          int    `json:"index"`
	Public         string `json:"share_public"`
	SignatureShare string `json:"signature_share"`
}

type AddSignatureResponse struct {
	T              int    `json:"t"`
	N              int    `json:"n"`
	Quorum         int    `json:"quorum"`
	AttestationJWT string `json:"attestation_jwt"`
}
