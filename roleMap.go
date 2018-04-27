package main

import (
	"fmt"
	"strings"
	"encoding/json"
	"context"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/logical"
)

func (b *backend) updateMap(requestRole role) {
	for _, policy := range requestRole.VaultPolicies {
		for roleName := range b.rolesMap {
			b.rolesMap[roleName] = unique(b.rolesMap[roleName])
			if contain(policy, b.rolesMap[roleName]) && !contain(roleName, requestRole.ChefRoles) {
				b.rolesMap[roleName] = remove(policy, b.rolesMap[roleName])
			}
		}
		for _, roleName := range requestRole.ChefRoles {
			if !contain(policy, b.rolesMap[roleName]) {
				b.rolesMap[roleName] = append(b.rolesMap[roleName], policy)
			}
			b.rolesMap[roleName] = unique(b.rolesMap[roleName])
		}
		for policyName := range b.policiesMap {
			b.policiesMap[policyName] = unique(b.policiesMap[policyName])
			if contain(policy, b.policiesMap[policyName]) && !contain(policyName, requestRole.ChefRoles) {
				b.policiesMap[policyName] = remove(policy, b.policiesMap[policyName])
			}
		}
		for _, policyName := range requestRole.ChefPolicyNames {
			if !contain(policy, b.policiesMap[policyName]) {
				b.policiesMap[policyName] = append(b.policiesMap[policyName], policy)
			}
			b.policiesMap[policyName] = unique(b.policiesMap[policyName])
		}
	}
	b.Logger().Info(spew.Sprint(b.rolesMap))
}

func (b *backend) deleteMap (ctx context.Context, req *logical.Request, roleName string) {
	raw, err := req.Storage.Get(ctx, fmt.Sprintf("%s%s", "role/", strings.ToLower(roleName)))
	if err != nil || raw == nil {
		return
	}
	role := &role{}
	err = json.Unmarshal(raw.Value, role)
	if err != nil {
		return
	}
	for _, policy := range role.VaultPolicies {
		for _, roleName := range role.ChefRoles {
			if contain(policy, b.rolesMap[roleName]) {
				b.rolesMap[roleName] = remove(policy, b.rolesMap[roleName])
			}
		}
		for _, policyName := range role.ChefPolicyNames {
			if contain(policy, b.policiesMap[roleName]) {
				b.policiesMap[policyName] = remove(policy, b.policiesMap[policyName])
			}
		}
	}
	b.Logger().Info(spew.Sprint(b.rolesMap))
}

func contain(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func remove(a string, list []string) []string {
	for i, b := range list {
		if b == a {
			list = unique(list)
			list = append(list[:i], list[i+1:]...)
			list = unique(list)
			return list
		}
	}
	list = unique(list)
	return list
}

func unique(intSlice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
