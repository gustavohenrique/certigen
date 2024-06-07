package jwt

type Jwt interface {
	GenerateToken(string) (string, error)
	ParseToken(string) (string, error)
}
