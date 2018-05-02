package main

import (
	"fmt"
	"errors"
	"context"

	"github.com/go-chef/chef"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"encoding/json"
	"time"
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

	raw, err := req.Storage.Get(ctx, "/config")
	if err != nil {
		return nil, err
	}

	if raw == nil {
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
		return nil, logical.ErrPermissionDenied
	}

	nodeRolesName := node.AutomaticAttributes["roles"].([]interface{})

	var policies []string
	var TTL time.Duration = -1
	var maxTTL time.Duration = -1
	var period time.Duration = -1

	b.RLock()
	defer b.RUnlock()

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
				"TTL": TTL,
				"maxTTL": maxTTL,
				"period": period,
			},
			Policies: policies,
			Metadata: map[string]string{
				"policies": node.PolicyName,
				"roles": fmt.Sprint(nodeRolesName),
				"host": conf.Host,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:		TTL,
				MaxTTL:		maxTTL,
				Renewable: true,
			},
		},
	}, nil
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	TTL := req.Auth.InternalData["TTL"].(time.Duration)
	maxTTL := req.Auth.InternalData["maxTTL"].(time.Duration)
	period := req.Auth.InternalData["period"].(time.Duration)

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.Period = period
	resp.Auth.TTL = TTL
	resp.Auth.MaxTTL = maxTTL
	return resp, nil
}