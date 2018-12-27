package security

const PICKLIST_CACHE_TIMEOUT = 120

type PicklistItem interface {
	GetKey() string
	GetValue() string
	GetDescription() string
	IsDeprecated() bool
}

type PicklistStore interface {
	GetPicklistItem(site, picklist, key string) (PicklistItem, error)
	GetPicklist(site, picklist string) (map[string]PicklistItem, error)
	GetPicklistOrdered(site, picklist string) ([]PicklistItem, error)
	AddPicklistItem(site, picklist, key, value, description string) error
	DeprecatePicklistItem(site, picklist, key string) error
	GetPicklists(site string) (map[string]map[string]PicklistItem, error)
}
