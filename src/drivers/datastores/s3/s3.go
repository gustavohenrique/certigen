package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3Config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type s3Store struct {
	client     *s3.Client
	bucket     string
	bucketLock sync.Mutex
}

type Config struct {
	Region string
	Bucket string
}

func New(config Config) S3Store {
	cfg, _ := s3Config.LoadDefaultConfig(
		context.Background(),
		s3Config.WithRegion(config.Region),
		// s3Config.WithLogConfigurationWarnings(true),
	)
	client := s3.NewFromConfig(cfg)
	return &s3Store{
		client: client,
		bucket: config.Bucket,
	}
}

func (s *s3Store) WithBucket(bucket string) S3Store {
	s.bucketLock.Lock()
	defer s.bucketLock.Unlock()
	s.bucket = bucket
	return s
}

func (s *s3Store) GetDownloadPresignedURL(ctx context.Context, objectKey string, lifetimeSecs int64) (string, error) {
	presigner := NewPresigner(s3.NewPresignClient(s.client))
	res, err := presigner.Download(ctx, s.getBucket(), objectKey, lifetimeSecs)
	return res.URL, err
}

func (s *s3Store) Download(ctx context.Context, objectKey string, filePath string) error {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.getBucket()),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return err
	}
	defer result.Body.Close()
	data, err := io.ReadAll(result.Body)
	if err != nil {
		return fmt.Errorf("failed reading the downloaded file %s", err)
	}
	return os.WriteFile(filePath, data, 0644)
}

func (s *s3Store) Upload(ctx context.Context, filePath string, objectKey ...string) error {
	file, err := s.getBytesFrom(filePath)
	if err != nil {
		return err
	}
	return s.UploadBytes(ctx, file, objectKey...)
}

func (s *s3Store) UploadBytes(ctx context.Context, content []byte, objectKey ...string) error {
	key := s.getFilename("", objectKey...)
	body := bytes.NewReader(content)
	bucket := s.getBucket()
	contentLength := int64(len(content))
	contentType := http.DetectContentType(content)
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(contentLength),
		ContentType:   aws.String(contentType),
	})
	return err
}

func (s *s3Store) UploadBigFile(ctx context.Context, filePath string, objectKey ...string) error {
	file, err := s.getBytesFrom(filePath)
	if err != nil {
		return err
	}
	largeBuffer := bytes.NewReader(file)
	var partMiBs int64 = 10
	uploader := manager.NewUploader(s.client, func(u *manager.Uploader) {
		u.PartSize = partMiBs * 1024 * 1024
	})
	filename := s.getFilename(filePath, objectKey...)
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.getBucket()),
		Key:    aws.String(filename),
		Body:   largeBuffer,
	})
	return err
}

func (s *s3Store) getBytesFrom(filePath string) ([]byte, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return []byte(""), fmt.Errorf("unable to open file %s, %v", filePath, err)
	}
	return file, nil
}

func (s *s3Store) getFilename(filePath string, objectKey ...string) string {
	filename := filepath.Base(filePath)
	if len(objectKey) > 0 {
		filename = objectKey[0]
	}
	return filename
}

func (s *s3Store) getBucket() string {
	s.bucketLock.Lock()
	defer s.bucketLock.Unlock()
	return s.bucket
}
