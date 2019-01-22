package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// ChefSearch represent a Chef search query that is refreshed at each Interval time
type ChefSearch struct {
	Name             string
	AllowedStaleness time.Duration
	Search           string
	Policies         []string
}

func pathSearch(b *backend) []*framework.Path {

	return []*framework.Path{
		{
			Pattern: "search-refresh",
			Fields:  map[string]*framework.FieldSchema{},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathSearchRefresh,
			},
			ExistenceCheck:  nil,
			HelpSynopsis:    "Remove the cache entries for saved searches.",
			HelpDescription: "Remove the cache entries for saved searches.",
		},
		{
			Pattern: "search/",
			Fields:  map[string]*framework.FieldSchema{},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathSearchList,
			},
			ExistenceCheck:  nil,
			HelpSynopsis:    "List all configured searches.",
			HelpDescription: "List all configured searches.",
		},
		{
			Pattern: "search/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeNameString,
					Description: "The desired name for the search.",
				},
				"allowed_staleness": {
					Type:        framework.TypeDurationSecond,
					Description: "An optional cache to avoid hitting too hard on Chef servers. 0 mean no cache.",
				},
				"search_query": {
					Type:        framework.TypeString,
					Description: "The SolR search query.",
				},
				"policies": {
					Type:        framework.TypeStringSlice,
					Description: "The policies which should get associated with matching nodes.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathSearchRead,
				logical.CreateOperation: b.pathSearchUpdateOrCreate,
				logical.UpdateOperation: b.pathSearchUpdateOrCreate,
				logical.DeleteOperation: b.pathSearchDelete,
			},
			ExistenceCheck:  b.pathSearchExistenceCheck,
			HelpSynopsis:    "CRUD operations on a single search",
			HelpDescription: "Let you read, update, create or delete a single search.",
		},
	}

}

func (b *backend) getSearchEntriesFromStorage(ctx context.Context, r *logical.Request) ([]*ChefSearch, error) {
	b.RLock()
	b.RUnlock()
	list, err := r.Storage.List(ctx, "search/")
	if err != nil {
		return nil, err
	}
	ret := []*ChefSearch{}
	// ret := make([]*ChefSearch, len(list))
	for _, sName := range list {
		s, err := b.getSearchEntryFromStorage(ctx, r, sName)
		if err != nil {
			return nil, err
		}
		ret = append(ret, s)
	}
	return ret, nil
}

func (b *backend) getSearchEntryFromStorage(ctx context.Context, r *logical.Request, name string) (*ChefSearch, error) {
	if name == "" {
		b.Logger().Warn("empty name passed in getSearchEntryFromStorage")
		return nil, fmt.Errorf("search's <name> is empty")
	}

	b.RLock()
	defer b.RUnlock()

	raw, err := r.Storage.Get(ctx, "search/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	search := &ChefSearch{}
	if err := json.Unmarshal(raw.Value, search); err != nil {
		return nil, err
	}
	return search, nil
}

func (b *backend) pathSearchRefresh(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.SearchStore.Range(func(key, value interface{}) bool {
		b.SearchStore.Delete(key)
		return true
	})
	return nil, nil
}

func (b *backend) pathSearchExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	p, err := b.getSearchEntryFromStorage(ctx, req, name)
	return p != nil, err
}

func (b *backend) pathSearchUpdateOrCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var err error
	var s *ChefSearch
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}
	search := d.Get("search_query").(string)
	if search == "" {
		return logical.ErrorResponse("missing search_query"), nil
	}
	if req.Operation == logical.UpdateOperation {
		s, err = b.getSearchEntryFromStorage(ctx, req, name)
		if err != nil {
			return nil, err
		}
	} else {
		s = &ChefSearch{
			Name:             name,
			Policies:         []string{},
			AllowedStaleness: 0,
			Search:           search,
		}
	}

	if policiesRaw, ok := d.GetOk("policies"); ok {
		s.Policies = policiesRaw.([]string)
	}

	if intervalRaw, ok := d.GetOk("allowed_staleness"); ok {
		s.AllowedStaleness = time.Duration(intervalRaw.(int)) * time.Second
	}

	b.Lock()
	defer b.Unlock()
	b.SearchStore.Delete(name)

	entry, err := logical.StorageEntryJSON("search/"+strings.ToLower(name), s)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathSearchRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	search, err := b.getSearchEntryFromStorage(ctx, req, name)
	if err != nil {
		return nil, err
	} else if search == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"policies":          search.Policies,
			"name":              search.Name,
			"search_query":      search.Search,
			"allowed_staleness": search.AllowedStaleness.Seconds(),
		},
	}

	return resp, nil
}

func (b *backend) getSearchList(ctx context.Context, req *logical.Request) ([]string, error) {
	b.RLock()
	b.RUnlock()
	return req.Storage.List(ctx, "search/")
}

func (b *backend) pathSearchList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.RLock()
	defer b.RUnlock()

	policies, err := req.Storage.List(ctx, "search/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(policies), nil
}

func (b *backend) pathSearchDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing search name"), nil
	}

	b.Lock()
	defer b.Unlock()

	if err := req.Storage.Delete(ctx, "search/"+strings.ToLower(name)); err != nil {
		return nil, err
	}
	return nil, nil
}
