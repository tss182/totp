package totp

import (
	"crypto/hmac"
	"fmt"
	"math"
	"net/url"
	"time"
)

type TOTP struct {
	Secret   string
	interval int64
	digit    int
	hashType hashType
	Url      string
}

func New(shaType, secret string) (t TOTP) {
	if secret == "" {
		t.Secret = RandomSecret(10)
	} else {
		t.Secret = secret
	}
	t.hashType = ShaSelect(shaType)
	if t.hashType.Label == "" {
		panic("totp: type sha")
	}
	t.digit = 6
	t.interval = 30
	return
}

func (t *TOTP) GetUrl(account, issuer string) string {
	query := url.Values{}
	label := url.PathEscape(account)
	if issuer != "" {
		label = url.PathEscape(issuer) + ":" + label
		query.Set("issuer", issuer)
	}
	query.Set("algorithm", t.hashType.Label)
	query.Set("secret", t.Secret)
	uri := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     label,
		RawQuery: query.Encode(),
	}
	t.Url = uri.String()
	return t.Url
}

func (t *TOTP) generateOTP(input int64) string {
	if input < 0 {
		panic("input must be positive integer")
	}
	hash := hmac.New(t.hashType.Hash, byteSecret(t.Secret))
	hash.Write(writeByte(input))
	hmacHash := hash.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	code = code % int(math.Pow10(t.digit))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", t.digit), code)
}

func (t *TOTP) Verify(otp string) bool {
	return otp == t.generateOTP(time.Now().Unix()/t.interval)
}
