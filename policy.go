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

// ChefPolicy represent a chef Policy that will be matched against the node-name runlist
type ChefPolicy struct {
	Name          string        `json:"name" structs:"name" mapstructure:"name"`
	VaultPolicies []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	TTL           time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL        time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Period        time.Duration `json:"period" structs:"period" mapstructure:"period"`
}

func pathPolicy(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "policy/",
			Fields:  map[string]*framework.FieldSchema{},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathPolicyList,
			},
			ExistenceCheck:  nil,
			HelpSynopsis:    "List all policies configured",
			HelpDescription: "List all policies configured",
		},
		{
			Pattern: "policy/" + framework.GenericNameRegex("name"),
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
				logical.ReadOperation:   b.pathPolicyRead,
				logical.UpdateOperation: b.pathPolicyUpdateOrCreate,
				logical.DeleteOperation: b.pathPolicyDelete,
			},
			ExistenceCheck:  b.pathPolicyExistenceCheck,
			HelpSynopsis:    "CRUD operations on a single policy",
			HelpDescription: "Let you read, update, create or delete a single policy.",
		},
	}

}

func (b *backend) getPolicyEntryFromStorage(ctx context.Context, r *logical.Request, name string) (*ChefPolicy, error) {
	if name == "" {
		b.Logger().Warn("empty name passed in getPolicyEntryFromStorage")
		return nil, fmt.Errorf("policy's <name> is empty")
	}

	b.RLock()
	defer b.RUnlock()

	raw, err := r.Storage.Get(ctx, "policy/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	p := &ChefPolicy{}
	if err := json.Unmarshal(raw.Value, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (b *backend) pathPolicyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	p, err := b.getPolicyEntryFromStorage(ctx, req, name)
	return p != nil, err
}

func (b *backend) pathPolicyUpdateOrCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var err error
	var p *ChefPolicy
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}
	if req.Operation == logical.UpdateOperation {
		p, err = b.getPolicyEntryFromStorage(ctx, req, name)
		if err != nil {
			return nil, err
		}
	} else {
		p = &ChefPolicy{
			Name:          name,
			VaultPolicies: []string{},
			TTL:           0,
			MaxTTL:        0,
			Period:        0,
		}
	}

	if policiesRaw, ok := d.GetOk("policies"); ok {
		p.VaultPolicies = policiesRaw.([]string)
	}

	if TTLRaw, ok := d.GetOk("ttl"); ok {
		p.TTL = TTLRaw.(time.Duration)
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		p.MaxTTL = maxTTLRaw.(time.Duration)
	}

	if periodRaw, ok := d.GetOk("period"); ok {
		p.Period = periodRaw.(time.Duration)
	}

	if p.TTL == 0 && p.Period == 0 {
		return nil, fmt.Errorf("you must provide either period or ttl")
	}

	if p.Period != 0 {
		p.MaxTTL = 0
		p.TTL = 0
	} else if p.MaxTTL < p.TTL {
		if p.MaxTTL != 0 {
			return nil, fmt.Errorf("max_ttl should always be left zero or be higher than ttl")
		}
		p.MaxTTL = p.TTL
	}

	b.Lock()
	defer b.Unlock()

	entry, err := logical.StorageEntryJSON("policy/"+strings.ToLower(name), p)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathPolicyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	policy, err := b.getPolicyEntryFromStorage(ctx, req, name)
	if err != nil {
		return nil, err
	} else if policy == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"policies": policy.VaultPolicies,
			"name":     policy.Name,
			"ttl":      policy.TTL,
			"max_ttl":  policy.MaxTTL,
			"period":   policy.Period,
		},
	}

	return resp, nil
}

func (b *backend) getPolicyList(ctx context.Context, req *logical.Request) ([]string, error) {
	b.RLock()
	b.RUnlock()
	return req.Storage.List(ctx, "policy/")
}

func (b *backend) pathPolicyList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.RLock()
	defer b.RUnlock()

	policies, err := req.Storage.List(ctx, "policy/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(policies), nil
}

func (b *backend) pathPolicyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing policy name"), nil
	}

	b.Lock()
	defer b.Unlock()

	if err := req.Storage.Delete(ctx, "policy/"+strings.ToLower(name)); err != nil {
		return nil, err
	}
	return nil, nil
}
