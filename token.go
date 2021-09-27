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
func NewToken(userid string, conf Config, accessExp, refreshExp time.Duration) (*Token, error) {
	token := &Token{
		Conf: conf,
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
		return t.Conf.Secret(), nil
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
		return t.Conf.Secret(), nil
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
func (t *Token) accessToken(userid string, exp time.Duration) (string, error) {
	if t.Conf == nil {
		return "", errors.New("Invalid Conf")
	}
	claims := jwt.MapClaims{}
	claims["user_id"] = userid
	claims["random"] = time.Now().Unix()
	if exp > 0 {
		claims["exp"] = time.Now().Add(exp).Unix()
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
func (t *Token) refreshToken(accessToken string, exp time.Duration) (string, error) {
	if t.Conf == nil {
		return "", errors.New("Invalid Conf")
	}
	claims := jwt.MapClaims{}
	claims["token"] = accessToken
	claims["random"] = time.Now().Nanosecond()
	if exp > 0 {
		claims["exp"] = time.Now().Add(exp).Unix()
	}
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := tk.SignedString(t.Conf.Secret())
	if err != nil {
		return token, err
	}
	return token, nil
}
