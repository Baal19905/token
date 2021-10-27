package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AccessClaims struct {
	UserId string        `json:"uid"`
	Expire time.Duration `json:"exp"`
	Random int           `json:"rdm"`
}

type RefreshClaims struct {
	AccessToken string        `json:"atk"`
	Expire      time.Duration `json:"exp"`
	Random      int           `json:"rdm"`
}

func newWithAccessClaims(userId string, exp time.Duration) *AccessClaims {
	var expireTime time.Duration
	if exp != 0 {
		expireTime = time.Duration(time.Now().Add(exp).Nanosecond())
	} else {
		expireTime = 0
	}
	return &AccessClaims{
		UserId: userId,
		Expire: expireTime,
		Random: time.Now().Nanosecond(),
	}
}

func newWithRefreshClaims(accessToken string, exp time.Duration) *RefreshClaims {
	var expireTime time.Duration
	if exp != 0 {
		expireTime = time.Duration(time.Now().Add(exp).Nanosecond())
	} else {
		expireTime = 0
	}
	return &RefreshClaims{
		AccessToken: accessToken,
		Expire:      expireTime,
		Random:      time.Now().Nanosecond(),
	}
}

func (c AccessClaims) Valid() error {
	if c.Expire == 0 {
		return nil // 永久有效
	}
	if time.Now().After(time.Unix(0, int64(c.Expire))) {
		vErr := new(jwt.ValidationError)
		vErr.Inner = errors.New("Token is expired")
		vErr.Errors |= jwt.ValidationErrorExpired
		return vErr
	}
	return nil
}

func (c RefreshClaims) Valid() error {
	if c.Expire == 0 {
		return nil // 永久有效
	}
	if time.Now().After(time.Unix(0, int64(c.Expire))) {
		vErr := new(jwt.ValidationError)
		vErr.Inner = errors.New("Token is expired")
		vErr.Errors |= jwt.ValidationErrorExpired
		return vErr
	}
	return nil
}
