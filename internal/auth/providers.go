package auth

const (
	ProviderGoogle = "google"
	ProviderUnsafe = "unsafe"
)

// ProviderUserData represents authorized user data from a provider
// it can be used to create an account or link to an existing one
type ProviderUserData struct {
	Provider string
	Email    string
	UserID   string
	Name     string
}
