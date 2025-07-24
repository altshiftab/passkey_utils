package public_key_credential_user_entity

type PublicKeyCredentialUserEntity struct {
	Name string `json:"name"`
	Id   []byte `json:"id"`
	DisplayName string `json:"displayName"`
}

func (u *PublicKeyCredentialUserEntity) GetName() string {
	return u.Name
}
