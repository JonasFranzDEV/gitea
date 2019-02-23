package transfer

// Transfer defines the structure of a transfer file for massimport into gitea
type Transfer struct {
	Users map[int64]*User
	Repos map[int64]*Repository
}
