package json

func FuzzJsonDecode(data []byte) int {
	Decode(data, &fixture{}, false)
	return 1
}
