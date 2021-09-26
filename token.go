package token

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	AccessToken  string
	RefreshToken string
}

var secret = []byte{61, 123, 96, 64, 41, 67, 35, 35, 41, 41, 36, 52, 56, 23, 31, 63, 37, 52, 98, 23, 25, 89, 47, 40, 42, 115, 100, 19, 102, 45, 87, 70}

// 生成双token
// 超时时间为0时永久有效
func NewToken(userid string, accessExp, refreshExp time.Duration) (*Token, error) {
	token := &Token{}
	var err error

	if token.AccessToken, err = accessToken(userid, accessExp); err != nil {
		return nil, err
	}

	if token.RefreshToken, err = refreshToken(token.AccessToken, refreshExp); err != nil {
		return nil, err
	}

	return token, nil
}

// 校验AccessToken
func (t *Token) ValidateAccessToken() (string, error) {
	token, err := jwt.Parse(t.AccessToken, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return "", err
	}

	payload, ok := token.Claims.(jwt.MapClaims)
	if !(ok && token.Valid) {
		return "", errors.New("invalid token")
	}
	return payload["user_id"].(string), nil
}

// 校验RefreshToken
func (t *Token) ValidateRefreshToken() (string, error) {
	token, err := jwt.Parse(t.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	if err != nil {
		return "", err
	}

	payload, ok := token.Claims.(jwt.MapClaims)
	if !(ok && token.Valid) {
		return "", errors.New("invalid token")
	}

	claims := jwt.MapClaims{}
	parser := jwt.Parser{}
	token, _, err = parser.ParseUnverified(payload["token"].(string), claims)
	if err != nil {
		return "", err
	}

	payload, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token")
	}
	return payload["user_id"].(string), nil
}

// 刷新双token
func (t *Token) Refresh(userid string, accessExp, refreshExp time.Duration) error {
	token, err := NewToken(userid, accessExp, refreshExp)
	if err != nil {
		return err
	}
	t.AccessToken = token.AccessToken
	t.RefreshToken = token.RefreshToken
	return nil
}

// 生成AccessToken
// exp为0时永久有效
func accessToken(userid string, exp time.Duration) (string, error) {
	claims := jwt.MapClaims{}
	claims["user_id"] = userid
	claims["random"] = time.Now().Unix()
	if exp > 0 {
		claims["exp"] = time.Now().Add(exp).Unix()
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := t.SignedString(secret)
	if err != nil {
		return "", err
	}
	return token, err
}

// 生成RefreshToken
// exp为0时永久有效
func refreshToken(accessToken string, exp time.Duration) (string, error) {
	claims := jwt.MapClaims{}
	claims["token"] = accessToken
	claims["random"] = time.Now().Nanosecond()
	if exp > 0 {
		claims["exp"] = time.Now().Add(exp).Unix()
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := t.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		return token, err
	}
	return token, nil
}
