package errcode

import (
	"encoding/json"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"testing"
)

func FuzzErrcode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)
		fuzzErrorCode, err := fdp.GetBool()
		if err != nil {
			return
		}
		if fuzzErrorCode {
			var ec ErrorCode
			if err := json.Unmarshal(data, &ec); err != nil {
				return
			}
			_ = ec.Error()
			_ = ec.String()
			_ = ec.Message()
			_, _ = ec.MarshalText()

			_ = ParseErrorCode(string(data))
		} else {
			var er Errors
			err = fdp.GenerateStruct(&er)
			if err == nil {
				d, err := fdp.GetBytes()
				if err != nil {
					return
				}
				er.UnmarshalJSON(d)
				_, _ = er.MarshalJSON()
			}

		}
		return
	})
}
