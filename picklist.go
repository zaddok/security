package security

const PICKLIST_CACHE_TIMEOUT = 120

// PicklistItem contains an element of a picklist displayed on a web page.
// Picklist items are sorted by index (numerically), then by value
// (alphabetically). Deprecated items do not appear in picklists,
// but may appear in legacy data, and will appear in a picklist when
// that data record has previously been set to include that deprecated.
type PicklistItem interface {
	// GetKey returns the short lowercase code for this picklist item
	GetKey() string

	// GetValue returns the visible human readable name of the picklist item
	GetValue() string

	// GetDescription retrns text typically used in help menus
	GetDescription() string

	// GetIndex returns a number used to override the natural alphabetical sort order
	GetIndex() int64

	IsDeprecated() bool

	// GetPicklistName returns the name of the picklist this item belogs to
	GetPicklistName() string
}

type PicklistStore interface {
	GetPicklistItem(site, picklist, key string) (PicklistItem, error)
	GetPicklistValue(site, picklist, key string) (string, error)
	GetPicklist(site, picklist string) (map[string]PicklistItem, error)

	// GetPicklistOrdered returns all items in the list sorted numerically by `index`, then alphabetically by `value`.
	GetPicklistOrdered(site, picklist string) ([]PicklistItem, error)

	AddPicklistItem(site, picklist, key, value, description string, index int64) error
	AddPicklistItemDeprecated(site, picklist, key, value, description string, index int64) error
	DeprecatePicklistItem(site, picklist, key string) error
	TogglePicklistItem(site, picklist, key string) error
	GetPicklists(site string) (map[string]map[string]PicklistItem, error)
}
