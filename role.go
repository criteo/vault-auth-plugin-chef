package main

import (
	"strings"
	"fmt"
	"encoding/json"
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/helper/policyutil"
)

type role struct {
	VaultPolicies   []string `json:"policies" structs:"policies" mapstructure:"policies"`
	ChefPolicyNames []string `json:"policy_names" structs:"policy_names" mapstructure:"policy_names"`
	ChefRoles       []string `json:"roles" structs:"roles" mapstructure:"roles"`
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	b.RLock()
	defer b.RUnlock()

	name := d.Get("name").(string)

	raw, err := req.Storage.Get(ctx, fmt.Sprintf("%s%s", "role/", strings.ToLower(name)))
	if err != nil {
		return false, err
	}
	if raw == nil {
		return false, nil
	}

	role := &role{}
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

	b.deleteMap(ctx, req, name)

	raw, err := req.Storage.Get(ctx, fmt.Sprintf("%s%s", "role/", strings.ToLower(name)))
	if err != nil {
		return nil, err
	}

	role := &role{}
	if raw == nil && req.Operation == logical.UpdateOperation {
		return nil, fmt.Errorf("role entry not found during update operation")
	}

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
		role.ChefRoles = d.Get("roles").([]string)
	}

	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(name), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for role %s", name)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	b.updateMap(*role)
	for _, roleName := range role.ChefRoles {
		for _, policy := range role.VaultPolicies {
			b.rolesMap[roleName] = append(b.rolesMap[roleName], policy)
		}
	}

	for _, policyName := range role.ChefPolicyNames {
		for _, policy := range role.VaultPolicies {
			b.policiesMap[policyName] = append(b.policiesMap[policyName], policy)
		}
	}
	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	b.RLock()
	defer b.RUnlock()

	raw, err := req.Storage.Get(ctx, fmt.Sprintf("%s%s", "role/", strings.ToLower(name)))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := &role{}
	if err := json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"policies":			role.VaultPolicies,
			"policy_names":     role.ChefPolicyNames,
			"roles":            role.ChefRoles,
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

	b.deleteMap(ctx, req, roleName)

	if err := req.Storage.Delete(ctx, "role/"+strings.ToLower(roleName)); err != nil {
		return nil, err
	}
	return nil, nil
}

