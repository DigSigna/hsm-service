package valueobjects

import "context"

type tenantKeyType string

const tenantKey tenantKeyType = "tenant_id"

func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantKey, tenantID)
}

func TenantFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(tenantKey).(string)
	return t, ok
}
