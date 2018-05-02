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

	b.RLock()
	defer b.RUnlock()

	for _, policy := range b.policiesMap[node.PolicyName] {
		policies = append(policies, policy)
	}

	for _, roleName := range nodeRolesName {
		for _, policy := range b.rolesMap[roleName.(string)] {
			policies = append(policies, policy)
		}
	}

	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Policies: policies,
			Metadata: map[string]string{
				"policies": node.PolicyName,
				"roles": fmt.Sprint(nodeRolesName),
				"host": conf.Host,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       10 * time.Hour,
				Renewable: true,
			},
		},
	}, nil
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	secretValue := req.Auth.InternalData["secret_value"].(string)
	if secretValue != "abcd1234" {
		return nil, errors.New("internal data does not match")
	}

	return framework.LeaseExtend(10 * time.Hour, 2 * 24 * time.Hour, b.System())(ctx, req, d)
}