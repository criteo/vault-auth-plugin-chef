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

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"node_name": {
				Type:        framework.TypeString,
				Description: "The node name, can be often found at /etc/chef/client.rb.",
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "The private key, can be often found at /etc/chef/client.pem.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathAuthLogin,
		},
	}
}

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nodeName := d.Get("node_name").(string)
	if nodeName == "" {
		return logical.ErrorResponse("no node name provided"), nil
	}
	l := b.Logger().With("node_name", nodeName, "request", req.ID)

	privateKey := d.Get("private_key").(string)
	if privateKey == "" {
		return logical.ErrorResponse("no private key provided"), nil
	}

	b.RLock()
	defer b.RUnlock()

	raw, err := req.Storage.Get(ctx, "config")
	if err != nil {
		l.Error("error occured while saving chef host config: %s", err)
		return logical.ErrorResponse(fmt.Sprintf("Error while fetching config : %s", err)), err
	}

	if raw == nil {
		l.Warn("clients should not use an unconfigured backend.")
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
		l.Error("error occured while authentication chef host with %s: %s", conf.Host, err)
		return nil, logical.ErrPermissionDenied
	}

	var auth *logical.Auth

	var chefPolicy *ChefPolicy
	if err != nil {
		l.Error("error while fetching chef policy list from storage", err)
		return nil, err
	}
	if node.PolicyName != "" {
		chefPolicies, err := b.getPolicyList(ctx, req)
		l = l.With("policy", node.PolicyName)
		for _, p := range chefPolicies {
			if p == node.PolicyName {
				chefPolicy, err = b.getPolicyEntryFromStorage(ctx, req, p)
				if err != nil {
					l.Error("error while fetching chef policy %s from storage", err)
					return nil, err
				}
				if chefPolicy == nil {
					l.Error("can't fetch a listed chef policy named %s in storage", p)
					return nil, fmt.Errorf("cannot fetch chef policy %s from storage backend", p)
				}
				auth = &logical.Auth{
					DisplayName:  nodeName,
					LeaseOptions: logical.LeaseOptions{TTL: chefPolicy.TTL, MaxTTL: chefPolicy.MaxTTL, Renewable: true},
					Period:       chefPolicy.Period,
					Policies:     chefPolicy.VaultPolicies,
					Metadata:     map[string]string{"policy": chefPolicy.Name},
					GroupAliases: []*logical.Alias{
						{
							Name: "policy-" + chefPolicy.Name,
						},
					},
				}
			}
		}
	} else if nodeRolesNames := node.AutomaticAttributes["roles"].([]interface{}); nodeRolesNames != nil && len(nodeRolesNames) > 0 {
		nodeRoles := make([]string, 0, len(nodeRolesNames))
		chefRoles, err := b.getRoleList(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, nRaw := range nodeRolesNames {

			roleName, ok := nRaw.(string)
			if !ok {
				return nil, fmt.Errorf("Can't serialize role name %+v into a string", nRaw)
			}
			nodeRoles = append(nodeRoles, roleName)
		}
		for _, r := range nodeRoles {
			for _, cr := range chefRoles {

				if r == cr {
					l = l.With("role", r)
					chefRole, err := b.getRoleEntryFromStorage(ctx, req, r)
					if err != nil {
						l.Error("error while fetching chef role %s from storage", err)
						return nil, err
					}
					if chefRole == nil {
						l.Error("can't fetch a listed chef role named %s in storage", r)
						return nil, fmt.Errorf("cannot fetch chef role %s from storage backend", r)
					}
					auth = &logical.Auth{
						DisplayName:  nodeName,
						LeaseOptions: logical.LeaseOptions{TTL: chefRole.TTL, MaxTTL: chefRole.MaxTTL, Renewable: true},
						Period:       chefRole.Period,
						Policies:     chefRole.VaultPolicies,
						Metadata:     map[string]string{"role": chefRole.Name},
						GroupAliases: []*logical.Alias{},
					}
					// n is usually between 1 or 5, it's ok to loop again
					for _, r := range nodeRoles {
						auth.GroupAliases = append(auth.GroupAliases, &logical.Alias{Name: "role" + r})
					}
					break
				}
			}

		}

	}
	if auth == nil {
		return logical.ErrorResponse("no match found. permission denied."), nil
	}
	return &logical.Response{
		Auth: auth,
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
