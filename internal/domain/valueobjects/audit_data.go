package valueobjects

type AuditData struct {
	ServiceName  string
	EventType    string
	Operation    string
	ResourceID   string
	ResourceType string
	ActorType    string
	Success      bool
	StatusCode   string
	ErrMsg       string
	DurationMs   int64
	Metadata     map[string]interface{}
}
