package security

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"math/rand"
	"strings"
	"syscall"
	"time"
)

var seeded = false

func RandomString(size int) string {
	if !seeded {
		seeded = true
		rand.Seed(time.Now().UTC().UnixNano())
	}
	bytes := make([]byte, size)
	for i := 0; i < size; i++ {
		b := uint8(rand.Int31n(36))
		if b < 26 {
			bytes[i] = 'A' + b
		} else if b < 52 {
			bytes[i] = 'a' + (b - 26)
		} else {
			bytes[i] = '0' + (b - 52)
		}
	}
	return string(bytes)
}

func HashPassword(password string) *string {
	if password == "" {
		return nil
	}

	seed := RandomString(16)

	var h hash.Hash = sha256.New()
	h.Write([]byte(seed))
	h.Write([]byte(password))
	b := base64.StdEncoding.EncodeToString(h.Sum(nil))

	p := fmt.Sprintf("%s:%s", seed, b)
	return &p
}

func VerifyPassword(actualPassword string, password string) bool {
	if actualPassword == "" || password == "" {
		return false
	}

	part := strings.Split(actualPassword, ":")
	if len(part) != 2 {
		return false
	}

	var h hash.Hash = sha256.New()
	h.Write([]byte(part[0]))
	h.Write([]byte(password))
	b := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return b == part[1]
}

func NowMilliseconds() int64 {
	var tv syscall.Timeval
	syscall.Gettimeofday(&tv)
	return int64(tv.Sec)*1e3 + int64(tv.Usec)/1e3
}
