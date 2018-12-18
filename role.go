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

// ChefRole represent a chef Role that will be matched against the node-name runlist
type ChefRole struct {
	Name          string        `json:"name" structs:"name" mapstructure:"name"`
	VaultPolicies []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	TTL           time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL        time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Period        time.Duration `json:"period" structs:"period" mapstructure:"period"`
}

func pathRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/",
			Fields:  map[string]*framework.FieldSchema{},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
			ExistenceCheck:  nil,
			HelpSynopsis:    "List all policies configured",
			HelpDescription: "List all policies configured",
		},
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeNameString,
					Description: "The name of the chef policy.",
				},
				"policies": {
					Type:        framework.TypeStringSlice,
					Description: "The list of vault's policy to assign.",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The TTL of the generated tokens",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The Max TTL of the generated tokens",
				},
				"period": {
					Type:        framework.TypeDurationSecond,
					Description: "The Period of the generated tokens",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleUpdateOrCreate,
				logical.UpdateOperation: b.pathRoleUpdateOrCreate,
				logical.DeleteOperation: b.pathRoleDelete,
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    "CRUD operations on a single policy",
			HelpDescription: "Let you read, update, create or delete a single policy.",
		},
	}

}

func (b *backend) getRoleEntryFromStorage(ctx context.Context, r *logical.Request, name string) (*ChefRole, error) {
	if name == "" {
		b.Logger().Warn("empty name passed in getRoleEntryFromStorage")
		return nil, fmt.Errorf("role's <name> is empty")
	}

	b.RLock()
	defer b.RUnlock()

	raw, err := r.Storage.Get(ctx, "role/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	role := &ChefRole{}
	if err := json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}
	return role, nil
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	p, err := b.getRoleEntryFromStorage(ctx, req, name)
	return p != nil, err
}

func (b *backend) pathRoleUpdateOrCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var err error
	var r *ChefRole
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}
	if req.Operation == logical.UpdateOperation {
		r, err = b.getRoleEntryFromStorage(ctx, req, name)
		if err != nil {
			return nil, err
		}
	} else {
		r = &ChefRole{
			Name:          name,
			VaultPolicies: []string{},
			TTL:           0,
			MaxTTL:        0,
			Period:        0,
		}
	}

	if policiesRaw, ok := d.GetOk("policies"); ok {
		r.VaultPolicies = policiesRaw.([]string)
	}

	if TTLRaw, ok := d.GetOk("ttl"); ok {
		r.TTL = time.Duration(TTLRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		r.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if periodRaw, ok := d.GetOk("period"); ok {
		r.Period = time.Duration(periodRaw.(int)) * time.Second
	}

	if r.TTL == 0 && r.Period == 0 {
		return nil, fmt.Errorf("you must provide either period or ttl")
	}

	if r.Period != 0 {
		r.MaxTTL = 0
		r.TTL = 0
	} else if r.MaxTTL < r.TTL {
		if r.MaxTTL != 0 {
			return nil, fmt.Errorf("max_ttl should always be left zero or be higher than ttl")
		}
		r.MaxTTL = r.TTL
	}

	b.Lock()
	defer b.Unlock()

	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(name), r)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	role, err := b.getRoleEntryFromStorage(ctx, req, name)
	if err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"policies": role.VaultPolicies,
			"name":     role.Name,
			"ttl":      role.TTL.Seconds(),
			"max_ttl":  role.MaxTTL.Seconds(),
			"period":   role.Period.Seconds(),
		},
	}

	return resp, nil
}

func (b *backend) getRoleList(ctx context.Context, req *logical.Request) ([]string, error) {
	b.RLock()
	b.RUnlock()
	return req.Storage.List(ctx, "role/")
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.RLock()
	defer b.RUnlock()

	policies, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(policies), nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.Lock()
	defer b.Unlock()

	if err := req.Storage.Delete(ctx, "role/"+strings.ToLower(name)); err != nil {
		return nil, err
	}
	return nil, nil
}
