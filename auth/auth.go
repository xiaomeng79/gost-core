package auth

import "context"

const (
	// 不需要认证
	AUTH_NOT_NEED int64 = 0
	// 认证不通过
	AUTH_NOT_PASSED int64 = -1
)

const (
	USER_ID = "user_id"
)

// Authenticator is an interface for user authentication.
type Authenticator interface {
	// 0：不需要认证 -1：认证不通过
	Authenticate(ctx context.Context, user, password string) int64
}

type authenticatorGroup struct {
	authers []Authenticator
}

func AuthenticatorGroup(authers ...Authenticator) Authenticator {
	return &authenticatorGroup{
		authers: authers,
	}
}

func (p *authenticatorGroup) Authenticate(ctx context.Context, user, password string) int64 {
	if len(p.authers) == 0 {
		return AUTH_NOT_NEED
	}
	for _, auther := range p.authers {
		if auther != nil {
			if id := auther.Authenticate(ctx, user, password); id != AUTH_NOT_PASSED {
				return id
			}
		}
	}
	return AUTH_NOT_PASSED
}
