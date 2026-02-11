package valueobjects

type OwnerType string

const (
	OwnerTypeTenant       OwnerType = "TENANT"
	OwnerTypeUser         OwnerType = "USER"
	OwnerTypeOrganization OwnerType = "ORGANIZATION"
)

func (ot OwnerType) IsValid() bool {
	switch ot {
	case OwnerTypeTenant, OwnerTypeUser, OwnerTypeOrganization:
		return true
	default:
		return false
	}
}
