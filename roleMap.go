package main

import (
	"fmt"
	"strings"
	"encoding/json"
	"context"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/logical"
)

func (b *backend) updateMap(requestRole *role) {
	for roleName := range b.rolesMap {
		b.rolesMap[roleName] = unique(b.rolesMap[roleName])
		if contain(requestRole, b.rolesMap[roleName]) && !sContain(roleName, requestRole.ChefRoles) {
			b.rolesMap[roleName] = remove(requestRole, b.rolesMap[roleName])
		}
	}
	for _, roleName := range requestRole.ChefRoles {
		if !contain(requestRole, b.rolesMap[roleName]) {
			b.rolesMap[roleName] = append(b.rolesMap[roleName], requestRole)
		}
		b.rolesMap[roleName] = unique(b.rolesMap[roleName])
	}
	for policyName := range b.policiesMap {
		b.policiesMap[policyName] = unique(b.policiesMap[policyName])
		if contain(requestRole, b.policiesMap[policyName]) && !sContain(policyName, requestRole.ChefRoles) {
			b.policiesMap[policyName] = remove(requestRole, b.policiesMap[policyName])
		}
	}
	for _, policyName := range requestRole.ChefPolicyNames {
		if !contain(requestRole, b.policiesMap[policyName]) {
			b.policiesMap[policyName] = append(b.policiesMap[policyName], requestRole)
		}
		b.policiesMap[policyName] = unique(b.policiesMap[policyName])
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
	for _, roleName := range role.ChefRoles {
		if contain(role, b.rolesMap[roleName]) {
			b.rolesMap[roleName] = remove(role, b.rolesMap[roleName])
		}
	}
	for _, policyName := range role.ChefPolicyNames {
		if contain(role, b.policiesMap[roleName]) {
			b.policiesMap[policyName] = remove(role, b.policiesMap[policyName])
		}
	}
	b.Logger().Info(spew.Sprint(b.rolesMap))
}

func contain(a *role, list []*role) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func sContain(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}


func remove(a *role, list []*role) []*role {
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

func unique(intSlice []*role) []*role {
	keys := make(map[*role]bool)
	var list []*role
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
