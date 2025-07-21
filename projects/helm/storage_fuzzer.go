package storage

import (
	"helm.sh/helm/v4/pkg/storage/driver"
	rspb "helm.sh/helm/v4/pkg/release/v1"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzStorage(data []byte) int {
	f := fuzz.NewConsumer(data)
	noOfCalls, err := f.GetInt()
	if err != nil {
		return 0
	}
	storage := Init(driver.NewMemory())
	for i:=0;i<noOfCalls%10;i++ {
		callType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch callType%11 {
		case 0:
			storageCreate(storage, f)
		case 1:
			storageUpdate(storage, f)
		case 2:
			storageGet(storage, f)
		case 3:
			storageDelete(storage, f)
		case 4:
			storageHistory(storage, f)
		case 5:
			storageListReleases(storage)
		case 6:
			storageListUninstalled(storage)
		case 7:
			storageListDeployed(storage)
		case 8:
			storageDeployed(storage, f)
		case 9:
			storageDeployedAll(storage, f)
		case 10:
			storageLast(storage, f)
		}
	}
	return 1
}

func storageCreate(s *Storage, f *fuzz.ConsumeFuzzer) error {
	rls := &rspb.Release{}
	err := f.GenerateStruct(rls)
	if err != nil {
		return err
	}
	s.Create(rls)
	return nil
}

func storageUpdate(s *Storage, f *fuzz.ConsumeFuzzer) error {
	rls := &rspb.Release{}
	err := f.GenerateStruct(rls)
	if err != nil {
		return err
	}
	s.Update(rls)
	return nil
}

func storageGet(s *Storage, f *fuzz.ConsumeFuzzer) error {
	name, err := f.GetString()
	if err != nil {
		return err
	}
	version, err := f.GetInt()
	if err != nil {
		return err
	}
	_, _ = s.Get(name, version)
	return nil
}

func storageDelete(s *Storage, f *fuzz.ConsumeFuzzer) error {
	name, err := f.GetString()
	if err != nil {
		return err
	}
	version, err := f.GetInt()
	if err != nil {
		return err
	}
	_, _ = s.Delete(name, version)
	return nil
}

func storageHistory(s *Storage, f *fuzz.ConsumeFuzzer) error {
	name, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = s.History(name)
	return nil
}

func storageListReleases(s *Storage) error {
	_, _ = s.ListReleases()
	return nil
}

func storageListUninstalled(s *Storage) error {
	_, _ = s.ListUninstalled()
	return nil
}

func storageListDeployed(s *Storage) error {
	_, _ = s.ListDeployed()
	return nil
}

func storageDeployed(s *Storage, f *fuzz.ConsumeFuzzer) error {
	name, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = s.Deployed(name)
	return nil
}

func storageDeployedAll(s *Storage, f *fuzz.ConsumeFuzzer) error {
	name, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = s.DeployedAll(name)
	return nil
}

func storageLast(s *Storage, f *fuzz.ConsumeFuzzer) error {
	name, err := f.GetString()
	if err != nil {
		return err
	}
	_, _ = s.Last(name)
	return nil
}
