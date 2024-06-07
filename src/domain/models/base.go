package models

import "time"

type Certificate struct {
	ID        string
	CreatedAt *time.Time
	Org       string
}
