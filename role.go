package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Role represent a mapping between chef information and vault policy and tokens
type Role struct {
	VaultPolicies   []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	ChefPolicyNames []string      `json:"policy_names" structs:"policy_names" mapstructure:"policy_names"`
	ChefRoles       []string      `json:"roles" structs:"roles" mapstructure:"roles"`
	TTL             time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL          time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Period          time.Duration `json:"period" structs:"period" mapstructure:"period"`
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	b.RLock()
	defer b.RUnlock()

	name := d.Get("name").(string)

	raw, err := req.Storage.Get(ctx, "role/"+strings.ToLower(name))
	if err != nil {
		return false, err
	}
	if raw == nil {
		return false, nil
	}

	role := &Role{}
	if err := json.Unmarshal(raw.Value, role); err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.RLock()
	defer b.RUnlock()

	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.Lock()
	defer b.Unlock()

	// b.deleteMap(ctx, req, name)

	raw, err := req.Storage.Get(ctx, "role/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}

	role := &Role{}
	if raw == nil && req.Operation == logical.UpdateOperation {
		return nil, fmt.Errorf("role entry not found during update operation")
	}

	// Updating or initializing role members
	if policiesRaw, ok := d.GetOk("policies"); ok {
		role.VaultPolicies = policyutil.ParsePolicies(policiesRaw)
	}

	if policyNames, ok := d.GetOk("policy_names"); ok {
		role.ChefPolicyNames = policyNames.([]string)
	} else if req.Operation == logical.CreateOperation {
		role.ChefPolicyNames = d.Get("policy_names").([]string)
	}

	if roles, ok := d.GetOk("roles"); ok {
		role.ChefRoles = roles.([]string)
	} else if req.Operation == logical.CreateOperation {
		role.ChefRoles = []string{}
	}

	if ttl, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttl.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.TTL = 0
	}

	if maxTTL, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTL.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.MaxTTL = 0
	}

	if period, ok := d.GetOk("period"); ok {
		role.Period = time.Duration(period.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.Period = 0
	}

	// If no MaxTTL, use TTL
	if role.MaxTTL == 0 {
		role.MaxTTL = role.TTL
	}

	// If both Period and TTL are 0, it's not good
	if role.TTL == 0 && role.Period == 0 {
		return nil, fmt.Errorf("You have to specify either period or ttl")
	}

	// Serializing json
	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(name), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for role %s", name)
	}
	// Updating Storage
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// b.updateMap(role)

	// for _, roleName := range role.ChefRoles {
	// 	b.rolesMap[roleName] = append(b.rolesMap[roleName], role)
	// }

	// for _, policyName := range role.ChefPolicyNames {
	// 	b.policiesMap[policyName] = append(b.policiesMap[policyName], role)
	// }
	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	b.RLock()
	defer b.RUnlock()

	raw, err := req.Storage.Get(ctx, "role/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := &Role{}
	if err := json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"policies":     role.VaultPolicies,
			"policy_names": role.ChefPolicyNames,
			"roles":        role.ChefRoles,
			"ttl":          role.TTL,
			"max_ttl":      role.MaxTTL,
			"period":       role.Period,
		},
	}

	return resp, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.Lock()
	defer b.Unlock()

	// b.deleteMap(ctx, req, roleName)

	if err := req.Storage.Delete(ctx, "role/"+strings.ToLower(roleName)); err != nil {
		return nil, err
	}
	return nil, nil
}
