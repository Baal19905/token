package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// 配置接口
type Config interface {
	Secret() []byte // 用于Token包获取Secret
}

// 双Token
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Conf         Config `json:"-"`
}

// 生成双token
// 超时时间为0时永久有效
func NewToken(userId string, conf Config, accessExp, refreshExp time.Duration) (*Token, error) {
	token := &Token{
		Conf: conf,
	}
	var err error
	accessClaims := newWithAccessClaims(userId, accessExp)
	if token.AccessToken, err = token.accessToken(accessClaims); err != nil {
		return nil, err
	}
	refreshClaimes := newWithRefreshClaims(token.AccessToken, refreshExp)
	if token.RefreshToken, err = token.refreshToken(refreshClaimes); err != nil {
		return nil, err
	}

	return token, nil
}

// 校验AccessToken
func (t *Token) ValidateAccessToken() (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(t.AccessToken, &AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.Conf.Secret(), nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token.Claims.(*AccessClaims), nil
}

// 校验RefreshToken
func (t *Token) ValidateRefreshToken() (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(t.RefreshToken, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.Conf.Secret(), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token.Claims.(*RefreshClaims), nil
}

// 刷新双token
func (t *Token) Refresh(userid string, conf Config, accessExp, refreshExp time.Duration) error {
	token, err := NewToken(userid, conf, accessExp, refreshExp)
	if err != nil {
		return err
	}
	t.AccessToken = token.AccessToken
	t.RefreshToken = token.RefreshToken
	return nil
}

// Token转换JSON
func (t *Token) Token2JSON() (string, error) {
	buf, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// JSON转换Token
func (t *Token) JSON2Token(j string, conf Config) error {
	if err := json.Unmarshal([]byte(j), t); err != nil {
		return err
	}
	t.Conf = conf
	return nil
}

// 生成AccessToken
// exp为0时永久有效
func (t *Token) accessToken(claims jwt.Claims) (string, error) {
	if t.Conf == nil {
		return "", errors.New("invalid conf")
	}
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := tk.SignedString(t.Conf.Secret())
	if err != nil {
		return "", err
	}
	return token, err
}

// 生成RefreshToken
// exp为0时永久有效
func (t *Token) refreshToken(claims jwt.Claims) (string, error) {
	if t.Conf == nil {
		return "", errors.New("invalid conf")
	}
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := tk.SignedString(t.Conf.Secret())
	if err != nil {
		return token, err
	}
	return token, nil
}
