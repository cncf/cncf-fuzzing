package digestset

import (

	digest "github.com/opencontainers/go-digest"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzDigestSet(data []byte) int {

	f := fuzz.NewConsumer(data)

	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}
	set := NewSet()
	for i:=0;i<noOfCalls%10;i++ {
		opType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch opType%5 {
		case 0:
			d, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = set.Lookup(d)
		case 1:
			dgstBytes, err := f.GetBytes()
			if err != nil {
				return 0
			}
			_ = set.Add(digest.FromBytes(dgstBytes))
		case 2:
			dgstBytes, err := f.GetBytes()
			if err != nil {
				return 0
			}
			_ = set.Remove(digest.FromBytes(dgstBytes))
		case 3:
			set.All()
		case 4:
			length, err := f.GetInt()
			if err != nil {
				return 0
			}
			_ = ShortCodeTable(set, length)
		}
	}

	return 1
}