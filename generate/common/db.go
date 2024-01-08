package common

type KeyShare struct {
	Index                    int    `json:"index"`
	PublicKey                []byte `json:"public_key"`
	PublicKeyHash            []byte `json:"public_key_hash"`
	SharePublic              []byte `json:"sharePublic"`
	EncryptedSharePrivateKey []byte `json:"encrypted_share_private_key"`
	ProvidedSignature        []byte `json:"provided_signature"`
}

type KeyState struct {
	T                  int32       `json:"t"`
	N                  int32       `json:"n"`
	Marker             string      `json:"marker"`
	SharePublicKey     []byte      `json:"share_public_key"`
	KeyShares          []*KeyShare `json:"key_shares"`
	Quorum             int32       `json:"quorum"`
	DataToSign         []byte      `json:"data_to_sign"`
	PublicKeyXOR       []byte      `json:"public_key_xor"`
	ParticipantKeyHash []string    `json:"participant_key_hash"`
}
