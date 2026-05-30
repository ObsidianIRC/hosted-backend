package main

import (
	"context"

	"backend/orca"
)

type ircAdapter struct{}

func (ircAdapter) Query(ctx context.Context, method string, params map[string]any) (any, error) {
	return ircQuery(method, params)
}

var _ orca.IRC = ircAdapter{}
