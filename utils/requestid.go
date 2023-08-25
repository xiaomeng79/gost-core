package utils

import (
	"context"

	"github.com/google/uuid"
)

// type requestID struct{}

const REQUEST_ID = "requestid"

func GetRequestID(ctx context.Context) string {
	if val := ctx.Value(REQUEST_ID); val != nil {
		if value, ok := val.(string); ok {
			return value
		}
	}
	return ""
}

func SetRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, REQUEST_ID, id)
}

func GetOrSetRequestID(ctx context.Context) (context.Context, string) {
	id := GetRequestID(ctx)
	if len(id) == 0 {
		id = uuid.New().String()
		ctx = SetRequestID(ctx, id)
	}
	return ctx, id
}
