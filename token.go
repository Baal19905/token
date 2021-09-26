package token

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Token struct {
	AccessToken  string
	RefreshToken string
	secret       []byte
}

// 生成双token
// 超时时间为0时永久有效
func NewToken(userid string, secret []byte, accessExp, refreshExp time.Duration) (*Token, error) {
	token := &Token{
		secret: secret,
	}
	var err error

	if token.AccessToken, err = token.accessToken(userid, accessExp); err != nil {
		return nil, err
	}

	if token.RefreshToken, err = token.refreshToken(token.AccessToken, refreshExp); err != nil {
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
		return t.secret, nil
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
	token, err := NewToken(userid, t.secret, accessExp, refreshExp)
	if err != nil {
		return err
	}
	t.AccessToken = token.AccessToken
	t.RefreshToken = token.RefreshToken
	return nil
}

// 生成AccessToken
// exp为0时永久有效
func (t *Token) accessToken(userid string, exp time.Duration) (string, error) {
	claims := jwt.MapClaims{}
	claims["user_id"] = userid
	claims["random"] = time.Now().Unix()
	if exp > 0 {
		claims["exp"] = time.Now().Add(exp).Unix()
	}
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := tk.SignedString(t.secret)
	if err != nil {
		return "", err
	}
	return token, err
}

// 生成RefreshToken
// exp为0时永久有效
func (t *Token) refreshToken(accessToken string, exp time.Duration) (string, error) {
	claims := jwt.MapClaims{}
	claims["token"] = accessToken
	claims["random"] = time.Now().Nanosecond()
	if exp > 0 {
		claims["exp"] = time.Now().Add(exp).Unix()
	}
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := tk.SignedString(t.secret)
	if err != nil {
		return token, err
	}
	return token, nil
}
