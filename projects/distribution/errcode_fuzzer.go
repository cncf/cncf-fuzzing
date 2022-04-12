package errcode

import (
	"encoding/json"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzErrcode(data []byte) int {
	f := fuzz.NewConsumer(data)
	fuzzErrorCode, err := f.GetBool()
	if err != nil {
		return 0
	}
	if fuzzErrorCode {
		var ec ErrorCode
		if err := json.Unmarshal(data, &ec); err != nil {
			return 0
		}
		_ = ec.Error()
		_ = ec.String()
		_ = ec.Message()
		_, _ = ec.MarshalText()

		_ = ParseErrorCode(string(data))
	} else {
		var er Errors
		err = f.GenerateStruct(&er)
		if err == nil {
			d, err := f.GetBytes()
			if err != nil {
				return 0
			}
			er.UnmarshalJSON(d)
			_, _ = er.MarshalJSON()
		}

	}
	


	return 1
}
