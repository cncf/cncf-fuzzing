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

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzInmemoryDriver(data []byte) int {
	d := New()
	f := fuzz.NewConsumer(data)
	noOfExecs, err := f.GetInt()
	if err != nil {
		return 0
	}
	maxExecs := noOfExecs % 10
	for i := 0; i < maxExecs; i++ {
		err = doRandomOp(d, f)
		if err != nil {
			return 0
		}
	}
	return 1
}

func doRandomOp(d *Driver, f *fuzz.ConsumeFuzzer) error {
	op, err := f.GetInt()
	if err != nil {
		return err
	}
	maxOps := 7
	if op%maxOps == 0 {
		err = putContent(d, f)
		if err != nil {
			return err
		}
	} else if op%maxOps == 1 {
		err = getContent(d, f)
		if err != nil {
			return err
		}
	} else if op%maxOps == 2 {
		err = write(d, f)
		if err != nil {
			return err
		}
	} else if op%maxOps == 3 {
		err = stat(d, f)
		if err != nil {
			return err
		}
	} else if op%maxOps == 4 {
		err = list(d, f)
		if err != nil {
			return err
		}
	} else if op%maxOps == 5 {
		err = doMove(d, f)
		if err != nil {
			return err
		}
	} else if op%maxOps == 6 {
		err = doDelete(d, f)
		if err != nil {
			return err
		}
	}
	return nil
}

func putContent(d *Driver, f *fuzz.ConsumeFuzzer) error {
	contents, err := f.GetBytes()
	if err != nil {
		return err
	}
	path, err := f.GetString()
	if err != nil {
		return err
	}
	_ = d.PutContent(context.Background(), path, contents)
	return nil
}

func getContent(d *Driver, f *fuzz.ConsumeFuzzer) error {
	path, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = d.GetContent(context.Background(), path)
	return nil
}

func write(d *Driver, f *fuzz.ConsumeFuzzer) error {
	path, err := f.GetString()
	if err != nil {
		return err
	}
	w, err := d.Writer(context.Background(), path, true)
	if err != nil {
		return err
	}
	p, err := f.GetBytes()
	if err != nil {
		return err
	}
	_, _ = w.Write(p)
	return nil
}

func stat(d *Driver, f *fuzz.ConsumeFuzzer) error {
	path, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = d.Stat(context.Background(), path)
	return nil
}

func list(d *Driver, f *fuzz.ConsumeFuzzer) error {
	path, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = d.List(context.Background(), path)
	return nil
}

func doMove(d *Driver, f *fuzz.ConsumeFuzzer) error {
	sourcePath, err := f.GetString()
	if err != nil {
		return err
	}
	destPath, err := f.GetString()
	if err != nil {
		return err
	}
	_ = d.Move(context.Background(), sourcePath, destPath)
	return nil
}

func doDelete(d *Driver, f *fuzz.ConsumeFuzzer) error {
	path, err := f.GetString()
	if err != nil {
		return err
	}
	_ = d.Delete(context.Background(), path)
	return nil
}
