package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"encoding/json"

	"github.com/go-chef/chef"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"node_name": {
			Type:        framework.TypeString,
			Description: "The node name, can be often found at /etc/chef/client.rb.",
		},
		"private_key": {
			Type:        framework.TypeString,
			Description: "The private key, can be often found at /etc/chef/client.pem.",
		},
	}
	callbks := map[logical.Operation]framework.OperationFunc{
		logical.UpdateOperation: b.pathAuthLogin,
	}
	return []*framework.Path{{
		Pattern:   "login",
		Fields:    fields,
		Callbacks: callbks,
	},
		{
			Pattern:   "login/" + framework.GenericNameRegex("node_name"),
			Fields:    fields,
			Callbacks: callbks,
		},
	}
}

func (b *backend) Login(ctx context.Context, req *logical.Request, nodeName, privateKey string) (*logical.Response, error) {
	l := b.Logger().With("node_name", nodeName, "request", req.ID)

	b.RLock()
	defer b.RUnlock()

	raw, err := req.Storage.Get(ctx, "config")
	if err != nil {
		l.Error("error occured while get chef host config: %s", err)
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
		Timeout: time.Second * 10,
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
					Policies:     append(chefPolicy.VaultPolicies, "default"),
					Metadata:     map[string]string{"policy": chefPolicy.Name, "node_name": nodeName},
					GroupAliases: []*logical.Alias{
						{
							Name: "policy-" + chefPolicy.Name,
						},
					},
					InternalData: map[string]interface{}{"private_key": privateKey},
				}
				break
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
		auth, err = func() (*logical.Auth, error) {
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
						auth := &logical.Auth{
							DisplayName:  nodeName,
							LeaseOptions: logical.LeaseOptions{TTL: chefRole.TTL, MaxTTL: chefRole.MaxTTL, Renewable: true},
							Period:       chefRole.Period,
							Policies:     append(chefRole.VaultPolicies, "default"),
							Metadata:     map[string]string{"role": chefRole.Name, "node_name": nodeName},
							GroupAliases: []*logical.Alias{},
							InternalData: map[string]interface{}{"private_key": privateKey},
						}
						// n is usually between 1 or 5, it's ok to loop again
						for _, r := range nodeRoles {
							auth.GroupAliases = append(auth.GroupAliases, &logical.Alias{Name: "role" + r})
						}
						return auth, nil
					}
				}
			}
			return nil, nil
		}()
		if err != nil {
			return nil, err
		}
	}

	if auth == nil {
		return logical.ErrorResponse("no match found. permission denied."), nil
	}

	if len(conf.DefaultPolicies) > 0 {
		auth.Policies = append(auth.Policies, conf.DefaultPolicies...)
	}

	policies, searches, err := b.MatchingSearches(req, client)
	if err != nil {
		l.Error(fmt.Sprintf("error while fetching matched searches: %s", err))
		return nil, err
	}
	if len(searches) > 0 {
		auth.Metadata["chef-matched-searches"] = strings.Join(searches, ",")
	}
	if len(policies) > 0 {
		auth.Policies = append(auth.Policies, policies...)
	}
	return &logical.Response{Auth: auth}, nil
}

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nodeName := d.Get("node_name").(string)
	if nodeName == "" {
		return logical.ErrorResponse("no node name provided"), nil
	}

	privateKey := d.Get("private_key").(string)
	if privateKey == "" {
		return logical.ErrorResponse("no private key provided"), nil
	}

	return b.Login(ctx, req, nodeName, privateKey)
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	b.Logger().Debug("received a renew request for %s", req.Auth.DisplayName)

	nodeName := req.Auth.Metadata["node_name"]
	if nodeName == "" {
		return logical.ErrorResponse("no node name provided"), nil
	}

	privateKeyRaw, ok := req.Auth.InternalData["private_key"]
	var privateKey string
	if ok {
		privateKey = privateKeyRaw.(string)
	}
	if privateKey == "" {
		return logical.ErrorResponse("no private key found"), nil
	}

	return b.Login(ctx, req, nodeName, privateKey)
}
