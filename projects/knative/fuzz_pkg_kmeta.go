package kmeta

import (
	"testing"
)

func FuzzChildName(f *testing.F) {
	f.Fuzz(func(t *testing.T, parent, suffix string) {
		_ = ChildName(parent, suffix)
	})
}
