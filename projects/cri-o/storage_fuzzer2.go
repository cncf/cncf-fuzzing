package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/containers/storage/pkg/archive"
	digest "github.com/opencontainers/go-digest"
	cp "github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/directory"
	"github.com/containers/image/v5/types"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	specs "github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/containers/image/v5/pkg/blobinfocache/memory"
	"github.com/containers/image/v5/signature"
)

var (
	compressions = []archive.Compression{archive.Uncompressed, archive.Gzip}
)

func makeLayer(f *fuzz.ConsumeFuzzer) ([]byte, digest.Digest, error) {
	compressionType, err := f.GetInt()
	if err != nil {
		return nil, "", err
	}
	compression := compressions[compressionType%len(compressions)]
	
	filename, err := f.GetString()
	if err != nil {
		return nil, "", err
	}

	fileContents, err := f.GetString()
	if err != nil {
		return nil, "", err
	}

	var compressed, uncompressed bytes.Buffer
	layer, err := archive.Generate(filename, fileContents)
	if err != nil {
		return nil, "", err
	}
	writer, err := archive.CompressStream(&compressed, compression)
	if err != nil {
		return nil, "", err
	}
	reader := io.TeeReader(layer, &uncompressed)
	_, err = io.Copy(writer, reader)
	writer.Close()
	if err != nil {
		return nil, "", err
	}
	return compressed.Bytes(), digest.FromBytes(uncompressed.Bytes()), nil
}

func getManifestBytes(blobBytes []byte, diffID digest.Digest) ([]byte, error) {
	blobInfo := types.BlobInfo{
		Digest: digest.FromBytes(blobBytes),
		Size:   int64(len(blobBytes)),
	}
	// Create a configuration that includes the diffID for the layer and not much else.
	config := v1.Image{
		RootFS: v1.RootFS{
			Type:    "layers",
			DiffIDs: []digest.Digest{diffID},
		},
	}
	configBytes, err := json.Marshal(&config)
	if err != nil {
		return []byte(""), err
	}
	configInfo := types.BlobInfo{
		Digest: digest.FromBytes(configBytes),
		Size:   int64(len(configBytes)),
	}
	// Create a manifest that uses this configuration and layer.
	manifest := v1.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		/*MediaType: v1.MediaTypeImageManifest,*/
		Config: v1.Descriptor{
			/*MediaType: v1.MediaTypeImageConfig,*/
			Digest:    configInfo.Digest,
			Size:      configInfo.Size,
		},
		Layers: []v1.Descriptor{{
			MediaType: v1.MediaTypeImageLayer,
			Digest:    blobInfo.Digest,
			Size:      blobInfo.Size,
		}},
	}
	manifestBytes, err := json.Marshal(&manifest)
	if err != nil {
		return []byte(""), err
	}
	return manifestBytes, nil
}

func Fuzz(data []byte) int {
	f := fuzz.NewConsumer(data)
	providedBlob, providedDigest, err := makeLayer(f)
	if err != nil {
		return 0
	}
	srcDir := "/tmp/srcdir"
	destDir := "/tmp/destDir"
	err = os.MkdirAll(srcDir, 0777)
	if err != nil {
		return 0
	}
	defer os.RemoveAll(srcDir)
	err = os.MkdirAll(destDir, 0777)
	if err != nil {
		return 0
	}
	defer os.RemoveAll(destDir)

	srcRef, err := directory.NewReference(srcDir)
	if err != nil {
		return 0
	}
	destImg, err := srcRef.NewImageDestination(context.Background(), nil)
	if err != nil {
		return 0
	}
	defer destImg.Close()
	
	cache := memory.New()
	providedInfo, err := destImg.PutBlob(context.Background(), bytes.NewReader(providedBlob), types.BlobInfo{Digest: providedDigest, Size: int64(len(providedBlob))}, cache, false)
	if err != nil {
		fmt.Println("PutBlob err: ", err)
		return 0
	}
	_ = providedInfo
	err = destImg.Commit(context.Background(), nil)
	if err != nil {
		fmt.Println(err)
		return 0
	}

	policyContext, err := signature.NewPolicyContext(&signature.Policy{
		Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()},
	})
	if err != nil {
		fmt.Println("err in policyContext: ", err)
		return 0
	}

	destRef, err := directory.NewReference(destDir)
	if err != nil {
		fmt.Println("err: ", err)
		return 0
	}
	_, _ = cp.Image(context.Background(), policyContext, destRef, srcRef, nil)
	return 1
}