package main

import (
	"context"
	"errors"
	"fmt"

	"encoding/json"
	"time"

	"github.com/go-chef/chef"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nodeName := d.Get("node_name").(string)
	if nodeName == "" {
		return logical.ErrorResponse("no node name provided"), nil
	}

	privateKey := d.Get("private_key").(string)
	if privateKey == "" {
		return logical.ErrorResponse("no private key provided"), nil
	}

	b.RLock()
	defer b.RUnlock()

	raw, err := req.Storage.Get(ctx, "config")
	if err != nil {
		b.Logger().Error("error occured while saving chef host config: %s", err)
		return logical.ErrorResponse(fmt.Sprintf("Error while fetching config : %s", err)), err
	}

	if raw == nil {
		b.Logger().Warn("clients should not use an unconfigured backend.")
		return logical.ErrorResponse("no host configured"), nil
	}

	conf := &config{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}

	client, err := chef.NewClient(&chef.Config{
		Name:    nodeName,
		Key:     privateKey,
		BaseURL: conf.Host,
		SkipSSL: true,
	})
	if err != nil {
		return nil, err
	}

	node, err := client.Nodes.Get(nodeName)
	if err != nil {
		b.Logger().Error("error occured while authentication chef host with %s: %s", conf.Host, err)
		return nil, logical.ErrPermissionDenied
	}

	nodeRolesName := node.AutomaticAttributes["roles"].([]interface{})

	var policies []string
	var TTL time.Duration = -1
	var maxTTL time.Duration = -1
	var period time.Duration = -1

	for _, role := range b.policiesMap[node.PolicyName] {
		for _, policy := range role.VaultPolicies {
			policies = append(policies, policy)
		}
		if TTL == -1 || role.TTL < TTL {
			TTL = role.TTL
		}
		if maxTTL == -1 || role.MaxTTL < maxTTL {
			maxTTL = role.MaxTTL
		}
		if period == -1 || role.Period < period {
			period = role.Period
		}
	}

	for _, roleName := range nodeRolesName {
		for _, role := range b.rolesMap[roleName.(string)] {
			for _, policy := range role.VaultPolicies {
				policies = append(policies, policy)
			}
			if TTL == -1 || role.TTL < TTL {
				TTL = role.TTL
			}
			if maxTTL == -1 || role.MaxTTL < maxTTL {
				maxTTL = role.MaxTTL
			}
			if period == -1 || role.Period < period {
				period = role.Period
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"TTL":    TTL.Seconds(),
				"maxTTL": maxTTL.Seconds(),
				"period": period.Seconds(),
			},
			Policies: policies,
			Metadata: map[string]string{
				"policies": node.PolicyName,
				"roles":    fmt.Sprint(nodeRolesName),
				"host":     conf.Host,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       TTL,
				MaxTTL:    maxTTL,
				Renewable: true,
			},
		},
	}, nil
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	TTL := time.Duration(req.Auth.InternalData["TTL"].(float64)) * time.Second
	maxTTL := time.Duration(req.Auth.InternalData["maxTTL"].(float64)) * time.Second
	period := time.Duration(req.Auth.InternalData["period"].(float64)) * time.Second

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.Period = period
	resp.Auth.TTL = TTL
	resp.Auth.MaxTTL = maxTTL
	return resp, nil
}
