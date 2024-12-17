// Copyright 2021 ADA Logics Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package inmemory

import (
	"context"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzInmemoryDriver(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		d := New()
		fdp := fuzz.NewConsumer(data)
		noOfExecs, err := fdp.GetInt()
		if err != nil {
			return
		}
		maxExecs := noOfExecs % 10
		for i := 0; i < maxExecs; i++ {
			err = doRandomOp(d, fdp)
			if err != nil {
				return
			}
		}
	})
}

func doRandomOp(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	op, err := fdp.GetInt()
	if err != nil {
		return err
	}
	maxOps := 7
	if op%maxOps == 0 {
		err = putContent(d, fdp)
		if err != nil {
			return err
		}
	} else if op%maxOps == 1 {
		err = getContent(d, fdp)
		if err != nil {
			return err
		}
	} else if op%maxOps == 2 {
		err = write(d, fdp)
		if err != nil {
			return err
		}
	} else if op%maxOps == 3 {
		err = stat(d, fdp)
		if err != nil {
			return err
		}
	} else if op%maxOps == 4 {
		err = list(d, fdp)
		if err != nil {
			return err
		}
	} else if op%maxOps == 5 {
		err = doMove(d, fdp)
		if err != nil {
			return err
		}
	} else if op%maxOps == 6 {
		err = doDelete(d, fdp)
		if err != nil {
			return err
		}
	}
	return nil
}

func putContent(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	contents, err := fdp.GetBytes()
	if err != nil {
		return err
	}
	path, err := fdp.GetString()
	if err != nil {
		return err
	}
	_ = d.PutContent(context.Background(), path, contents)
	return nil
}

func getContent(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	path, err := fdp.GetString()
	if err != nil {
		return err
	}
	_, _ = d.GetContent(context.Background(), path)
	return nil
}

func write(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	path, err := fdp.GetString()
	if err != nil {
		return err
	}
	w, err := d.Writer(context.Background(), path, true)
	if err != nil {
		return err
	}
	p, err := fdp.GetBytes()
	if err != nil {
		return err
	}
	_, _ = w.Write(p)
	return nil
}

func stat(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	path, err := fdp.GetString()
	if err != nil {
		return err
	}
	_, _ = d.Stat(context.Background(), path)
	return nil
}

func list(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	path, err := fdp.GetString()
	if err != nil {
		return err
	}
	_, _ = d.List(context.Background(), path)
	return nil
}

func doMove(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	sourcePath, err := fdp.GetString()
	if err != nil {
		return err
	}
	destPath, err := fdp.GetString()
	if err != nil {
		return err
	}
	_ = d.Move(context.Background(), sourcePath, destPath)
	return nil
}

func doDelete(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	path, err := fdp.GetString()
	if err != nil {
		return err
	}
	_ = d.Delete(context.Background(), path)
	return nil
}
