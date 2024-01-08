package common

type KeyShare struct {
	Index       int    `json:"index"`
	SharePublic string `json:"sharePublic"`
	Signature   string `json:"signature"`
}

type KeyState struct {
	T              int         `json:"t"`
	N              int         `json:"n"`
	Marker         string      `json:"marker"`
	SharePublicKey string      `json:"share_public_key"`
	KeyShares      []*KeyShare `json:"key_shares"`
	Quorum         int         `json:"quorum"`
	DataToSign     string      `json:"data_to_sign"`
	Signature      string      `json:"signature"`
}
