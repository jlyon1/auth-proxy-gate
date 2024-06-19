package auth

type Filter interface {
	Validate(data AuthorizedProviderUserData) bool
	Name() string
}

type EmailAllowListFilter struct {
	AllowedEmails []string
}

func (a *EmailAllowListFilter) Name() string {
	return "EmailAllowListFilter"
}

func (a *EmailAllowListFilter) Validate(data AuthorizedProviderUserData) bool {
	found := false

	for _, entry := range a.AllowedEmails {
		if entry == data.Email {
			found = true
			break
		}
	}

	if len(a.AllowedEmails) == 0 {
		found = true
	}

	return found
}

var _ Filter = (*EmailAllowListFilter)(nil)
