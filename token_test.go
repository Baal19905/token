package token

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var secretTest = []byte{61, 123, 96, 64, 41, 67, 35, 35, 41, 41, 36, 52, 56, 23, 31, 63, 37, 52, 98, 23, 25, 89, 47, 40, 42, 115, 100, 19, 102, 45, 87, 70}

func TestNewToken(t *testing.T) {
	token, err := NewToken("abcd", secretTest, 0, 0)
	if err != nil {
		t.Errorf("NewToken failed[%s]\n", err.Error())
		return
	}
	data, _ := json.Marshal(token)
	t.Logf("Token: %s\n", data)
	// 不序列化secret字段
	if strings.Contains(string(data), "secret") {
		t.Errorf("secret in JSON!!!\n")
	}
}

func TestValidateAccessToken(t *testing.T) {
	token, err := NewToken("abcd", secretTest, time.Second*5, 0)
	if err != nil {
		t.Errorf("NewToken failed， %s\n", err.Error())
		return
	}

	token2, err := NewToken("1234", secretTest, 0, 0)
	if err != nil {
		t.Errorf("NewToken failed， %s\n", err.Error())
		return
	}
	// 超时测试
	time.Sleep(time.Second * 6)
	t.Logf("--------------6 later---------------\n")
	userid, err := token.ValidateAccessToken()
	if userid != "abcd" || err != nil {
		t.Logf("AccessToken[%s] is expired\n", token.AccessToken)
	} else {
		t.Errorf("AccessToken[%s] is not expired after 6s!!!\n", token.AccessToken)
	}
	// 篡改测试
	tmp := []byte(token.AccessToken)
	tmp[0] += 1
	token.AccessToken = string(tmp)
	userid, err = token.ValidateAccessToken()
	if userid != "abcd" || err != nil {
		t.Logf("Invalid AccessToken[%s]\n", err.Error())
		return
	} else {
		t.Errorf("Valid AccessToken[%s] with change\n", token.AccessToken)
	}
	// 非本用户token测试
	userid, err = token2.ValidateAccessToken()
	if userid != "abcd" || err != nil {
		t.Logf("Invalid AccessToken[%s]\n", token.AccessToken)
	} else {
		t.Errorf("not the same user!!!\n")
	}
}

func TestValidateRefreshToken(t *testing.T) {
	token, err := NewToken("abcd", secretTest, 0, time.Second*5)
	if err != nil {
		t.Errorf("NewToken failed， %s\n", err.Error())
		return
	}

	token2, err := NewToken("1234", secretTest, 0, 0)
	if err != nil {
		t.Errorf("NewToken failed， %s\n", err.Error())
		return
	}
	// 超时测试
	time.Sleep(time.Second * 6)
	t.Logf("--------------6 later---------------\n")
	userid, err := token.ValidateRefreshToken()
	if userid != "abcd" || err != nil {
		t.Logf("RefreshToken[%s] is expired\n", token.RefreshToken)
	} else {
		t.Errorf("RefreshToken[%s] is not expired after 6s!!!\n", token.RefreshToken)
	}
	// 篡改测试
	tmp := []byte(token.RefreshToken)
	tmp[0] += 1
	token.RefreshToken = string(tmp)
	userid, err = token.ValidateRefreshToken()
	if userid != "abcd" || err != nil {
		t.Logf("Invalid RefreshToken[%s]\n", err.Error())
		return
	} else {
		t.Errorf("Valid RefreshToken[%s] with change\n", token.RefreshToken)
	}
	// 非本用户token测试
	userid, err = token2.ValidateRefreshToken()
	if userid != "abcd" || err != nil {
		t.Logf("Invalid RefreshToken[%s]\n", token.RefreshToken)
	} else {
		t.Errorf("not the same user!!!\n")
	}
}

func TestRefresh(t *testing.T) {
	token, err := NewToken("abcd", secretTest, 0, 0)
	if err != nil {
		t.Errorf("NewToken failed[%s]\n", err.Error())
		return
	}
	t.Logf("AccessToken[%s]\n", token.AccessToken)
	t.Logf("RefreshToken[%s]\n", token.RefreshToken)
	time.Sleep(time.Second)
	t.Logf("---------------After Refresh---------------\n")
	tmp := *token
	token.Refresh("abcd", 0, 0)
	if tmp.AccessToken == token.AccessToken || tmp.RefreshToken == token.RefreshToken {
		t.Error("Same Token after Refresh!!!\n")
	}
}

func TestJSON(t *testing.T) {
	token, err := NewToken("abcd", secretTest, 0, 0)
	if err != nil {
		t.Errorf("NewToken failed[%s]\n", err.Error())
		return
	}
	json, err := token.Token2JSON()
	if err != nil {
		t.Errorf("Token2JSON failed[%s]\n", err.Error())
		return
	}
	token2 := &Token{}
	if err := token2.JSON2Token(json); err != nil {
		t.Errorf("JSON2Token failed[%s]\n", err.Error())
		return
	}
	if token.AccessToken != token2.AccessToken || token.RefreshToken != token2.RefreshToken {
		t.Errorf("token != token2!!!\n")
	}
}
