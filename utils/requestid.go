package utils

import (
	"context"

	"github.com/google/uuid"
)

type RequestID struct{}

// const REQUEST_ID = "requestid"

func GetRequestID(ctx context.Context) string {
	if val := ctx.Value(RequestID{}); val != nil {
		if value, ok := val.(string); ok {
			return value
		}
	}
	return ""
}

func SetRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, RequestID{}, id)
}

func GetOrSetRequestID(ctx context.Context) (context.Context, string) {
	id := GetRequestID(ctx)
	if len(id) == 0 {
		id = uuid.New().String()
		ctx = SetRequestID(ctx, id)
	}
	return ctx, id
}
