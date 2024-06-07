package s3

import (
	"context"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type S3Store interface {
	UploadBytes(ctx context.Context, b []byte, objectKey ...string) error
	Upload(ctx context.Context, filePath string, objectKey ...string) error
	UploadBigFile(ctx context.Context, filePath string, objectKey ...string) error
	Download(ctx context.Context, objectKey string, filePath string) error
	GetDownloadPresignedURL(ctx context.Context, objectKey string, lifetimeSecs int64) (string, error)
}

type S3Presigner interface {
	Download(ctx context.Context, bucketName string, objectKey string, lifetimeSecs int64) (*v4.PresignedHTTPRequest, error)
	Upload(ctx context.Context, bucketName string, objectKey string, lifetimeSecs int64) (*v4.PresignedHTTPRequest, error)
	Delete(ctx context.Context, bucketName string, objectKey string) (*v4.PresignedHTTPRequest, error)
}
