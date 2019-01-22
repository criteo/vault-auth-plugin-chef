package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-chef/chef"
	"github.com/hashicorp/vault/logical"
)

func (b *backend) MatchingSearches(r *logical.Request, client *chef.Client) ([]string, []string, error) {
	policies := []string{}
	matchedSearches := []string{}
	searches, err := b.getSearchEntriesFromStorage(context.Background(), r)
	if err != nil {
		return nil, nil, err
	}
	for _, s := range searches {
		ok, err := b.isNodeInSearch(r, client, s)
		if err != nil {
			return nil, policies, err
		}
		if ok {
			policies = append(policies, s.Policies...)
			matchedSearches = append(matchedSearches, s.Name)
		}
	}
	return policies, matchedSearches, nil
}

func (b *backend) isNodeInSearch(r *logical.Request, client *chef.Client, s *ChefSearch) (bool, error) {
	nodes, err := b.nodesForSearch(r, client, s)
	if err != nil {
		return false, err
	}
	_, ok := nodes[client.Auth.ClientName]
	return ok, nil
}

func (b *backend) nodesForSearch(r *logical.Request, client *chef.Client, s *ChefSearch) (map[string]bool, error) {
	st := b.SearchStore
	name := s.Name
	if _, ok := st.Load(name); ok {
		return nil, nil
	}

	rs, err := client.Search.Exec("node", s.Search)
	if err != nil {
		return nil, fmt.Errorf("Error while executing the search: %s", err)
	}

	if len(rs.Rows) == 0 {
		b.Logger().Warn("search \"%s\" returned 0 entries", s.Name)
	}

	nodes := make(map[string]bool, len(rs.Rows))
	for _, nodeRaw := range rs.Rows {
		node, ok := nodeRaw.(map[string]interface{})
		if !ok {
			err := fmt.Errorf("Invalid type for data returned by Chef")
			b.Logger().Error(err.Error())
			return nil, err
		}
		nameRaw, ok := node["name"]
		if !ok {
			err := fmt.Errorf("Name is missing from the response of Chef")
			b.Logger().Error(err.Error())
			return nil, err
		}
		name, ok := nameRaw.(string)
		if !ok {
			err := fmt.Errorf("Name \"%+v\" is incorrect from the response of Chef", nameRaw)
			b.Logger().Error(err.Error())
			return nil, err
		}
		nodes[name] = true
	}
	if s.AllowedStaleness != 0 {
		st.Store(s.Name, nodes)
		time.AfterFunc(s.AllowedStaleness, func() { st.Delete(s.Name) })
	}
	return nodes, nil
}
