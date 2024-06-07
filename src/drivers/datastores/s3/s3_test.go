package s3_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"certigen/src/drivers/datastores/s3"
)

func TestS3Store(t *testing.T) {
	t.Skip()
	file := filepath.Join(".", "testdata", "hello.txt")
	store := s3.New(s3.Config{
		Region: "us-east-1",
		Bucket: "dev-core-go-certigen-bucket",
	})
	err := store.Upload(context.Background(), file)
	if err != nil {
		t.Fatalf("Upload %s failed:  %s", file, err)
	}

	err = store.Download(context.Background(), file, filepath.Join(os.TempDir(), "download-from-s3.txt"))
	if err != nil {
		t.Fatalf("Download %s failed: %s", file, err)
	}

	downloadURL, err := store.GetDownloadPresignedURL(context.Background(), file, 5*60)
	if err != nil {
		t.Fatalf("Get presigned URL for %s failed: %s", file, err)
	}
	fmt.Println("Presigned URL=", downloadURL)

}
