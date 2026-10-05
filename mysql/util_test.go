package mysql

import (
	"crypto/sha1"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCompareServerVersions(t *testing.T) {
	tests := []struct {
		A      string
		B      string
		Expect int
	}{
		{A: "1.2.3", B: "1.2.3", Expect: 0},
		{A: "5.6-999", B: "8.0", Expect: -1},
		{A: "5.6.3-999", B: "5.6", Expect: 0},
		{A: "5.6.3-999", B: "5.5-tag", Expect: 1},
		{A: "8.0.32-0ubuntu0.20.04.2", B: "8.0.28", Expect: 1},
		{A: "a.b.c", B: "8.0", Expect: 2},
	}

	for _, test := range tests {
		got, err := CompareServerVersions(test.A, test.B)
		if test.Expect == 2 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, test.Expect, got)
		}

		// test logic is commutative
		got, err = CompareServerVersions(test.B, test.A)
		if test.Expect == 2 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, -test.Expect, got)
		}
	}
}

func TestFormatBinaryTime(t *testing.T) {
	tests := []struct {
		Data   []byte
		Expect string
		Error  bool
	}{
		{Data: []byte{}, Expect: "00:00:00"},
		{Data: []byte{0, 0, 0, 0, 0, 0, 0, 10}, Expect: "00:00:10"},
		{Data: []byte{0, 0, 0, 0, 0, 0, 1, 40}, Expect: "00:01:40"},
		{Data: []byte{1, 0, 0, 0, 0, 0, 1, 40}, Expect: "-00:01:40"},
		{Data: []byte{1, 1, 0, 0, 0, 1, 1, 40}, Expect: "-25:01:40"},
		{Data: []byte{1, 1, 0, 0, 0, 1, 1, 40, 1, 2, 3, 0}, Expect: "-25:01:40.197121"},
		{Data: []byte{0}, Error: true},
	}

	for _, test := range tests {
		n := len(test.Data)

		got, err := FormatBinaryTime(n, test.Data)
		if test.Error {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, test.Expect, string(got), "test case %v", test.Data)
	}
}

func TestToBinaryDateTime(t *testing.T) {
	var (
		DateTimeNano         = "2006-01-02 15:04:05.000000"
		formatBinaryDateTime = func(n int, data []byte) string {
			date, err := FormatBinaryDateTime(n, data)
			if err != nil {
				return ""
			}
			return string(date)
		}
	)

	tests := []struct {
		Name   string
		Data   time.Time
		Expect func(n int, data []byte) string
		Error  bool
	}{
		{
			Name:   "Zero time",
			Data:   time.Time{},
			Expect: nil,
		},
		{
			Name:   "Date with nanoseconds",
			Data:   time.Date(2023, 10, 10, 10, 10, 10, 123456000, time.UTC),
			Expect: formatBinaryDateTime,
		},
		{
			Name:   "Date with time",
			Data:   time.Date(2023, 10, 10, 10, 10, 10, 0, time.UTC),
			Expect: formatBinaryDateTime,
		},
		{
			Name:   "Date only",
			Data:   time.Date(2023, 10, 10, 0, 0, 0, 0, time.UTC),
			Expect: formatBinaryDateTime,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			got, err := toBinaryDateTime(test.Data)
			if test.Error {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if len(got) == 0 {
				return
			}
			tmp := test.Expect(int(got[0]), got[1:])
			if int(got[0]) < 11 {
				require.Equal(t, tmp, test.Data.Format(time.DateTime), "test case %v", test.Data.String())
			} else {
				require.Equal(t, tmp, test.Data.Format(DateTimeNano), "test case %v", test.Data.String())
			}
		})
	}
}

// TestCalcNativePasswordFromStage1 confirms the stage1-based response is
// byte-identical to the plaintext-based one for the same scramble, so a
// caller holding only SHA1(password) produces exactly what a normal client
// would send.
func TestCalcNativePasswordFromStage1(t *testing.T) {
	seed := []byte("12345678901234567890")
	for _, pw := range []string{"a", "secret", "a much longer password with spaces"} {
		stage1 := sha1.Sum([]byte(pw))
		require.Equal(t,
			CalcNativePassword(seed, []byte(pw)),
			CalcNativePasswordFromStage1(seed, stage1[:]),
			"password %q", pw)
	}
	require.Nil(t, CalcNativePasswordFromStage1(seed, nil))
	require.Nil(t, CalcNativePasswordFromStage1(seed, []byte{}))
}

// TestRecoverNativePasswordStage1 covers the server side: a valid reply
// yields SHA1(password) and true; a reply for a different password, an
// empty stored hash, or a garbage reply yields (nil, false). It also checks
// the recovered value re-authenticates against a fresh scramble, which is
// the property proxies rely on.
func TestRecoverNativePasswordStage1(t *testing.T) {
	seed := []byte("12345678901234567890")
	pw := []byte("secret")
	stored := NativePasswordHash(pw)
	reply := CalcNativePassword(seed, pw)

	stage1, ok := RecoverNativePasswordStage1(reply, seed, stored)
	require.True(t, ok)
	want := sha1.Sum(pw)
	require.Equal(t, want[:], stage1)

	// CompareNativePassword must agree with the recovery result.
	require.True(t, CompareNativePassword(reply, stored, seed))

	// The recovered stage1 answers a different challenge correctly.
	seed2 := []byte("abcdefghijklmnopqrst")
	require.True(t, CompareNativePassword(CalcNativePasswordFromStage1(seed2, stage1), stored, seed2))

	// Wrong password.
	s, ok := RecoverNativePasswordStage1(CalcNativePassword(seed, []byte("wrong")), seed, stored)
	require.False(t, ok)
	require.Nil(t, s)
	require.False(t, CompareNativePassword(CalcNativePassword(seed, []byte("wrong")), stored, seed))

	// Empty stored hash never matches.
	s, ok = RecoverNativePasswordStage1(reply, seed, nil)
	require.False(t, ok)
	require.Nil(t, s)

	// Truncated / garbage reply.
	s, ok = RecoverNativePasswordStage1([]byte{1, 2, 3}, seed, stored)
	require.False(t, ok)
	require.Nil(t, s)
}
