package main

import (
	"context"
	"errors"
	"log"
	"os"
	"fmt"
	"encoding/json"
	"sync"

	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/logical/plugin"
	"github.com/go-chef/chef"
	"strings"
	"github.com/hashicorp/vault/helper/policyutil"
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	l sync.RWMutex
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
			SealWrapStorage: []string{"config"},
		},
		Paths: []*framework.Path{

			// Route Login
			&framework.Path{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"node_name": &framework.FieldSchema{
						Type: framework.TypeString,
					},
					"private_key": &framework.FieldSchema{
						Type: framework.TypeString,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthLogin,
				},
			},

			// Route Config
			&framework.Path{
				Pattern: "config",
				Fields: map[string]*framework.FieldSchema{
					"host": &framework.FieldSchema{
						Type: framework.TypeString,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathConfigWrite,
					logical.CreateOperation: b.pathConfigWrite,
					logical.ReadOperation: b.pathConfigRead,
				},
			},

			// Role Config
			&framework.Path{
				Pattern: "role/?",
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ListOperation: b.pathRoleList,
				},
			},
			&framework.Path{
				Pattern: "role/" + framework.GenericNameRegex("name"),
				Fields: map[string]*framework.FieldSchema{
					"name": &framework.FieldSchema{
						Type:        framework.TypeString,
					},
					"policies": &framework.FieldSchema{
						Type:        framework.TypeStringSlice,
					},
					"policy_names": &framework.FieldSchema{
						Type:        framework.TypeStringSlice,
					},
					"roles": &framework.FieldSchema{
						Type:        framework.TypeStringSlice,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.CreateOperation: b.pathRoleCreateUpdate,
					logical.UpdateOperation: b.pathRoleCreateUpdate,
					logical.ReadOperation:   b.pathRoleRead,
					logical.DeleteOperation: b.pathRoleDelete,
				},
			},
		},
	}

	return &b
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

	raw, err := req.Storage.Get(ctx, "/config")
	if err != nil {
		return nil, err
	}

	if raw == nil {
		return nil, nil
	}

	conf := &config{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}

	client, err := chef.NewClient(&chef.Config{
		Name: nodeName,
		Key: privateKey,
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

	policy := node.PolicyName
	roles := fmt.Sprint(node.AutomaticAttributes["roles"])

	fmt.Println(policy)
	fmt.Println(roles)

	ttl, _, err := b.SanitizeTTLStr("30s", "1h")
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Policies: []string{"my-policy", "other-policy"},
			Metadata: map[string]string{
				"policy": policy,
				"roles": roles,
				"host": conf.Host,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       ttl,
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

	ttl, maxTTL, err := b.SanitizeTTLStr("30s", "1h")
	if err != nil {
		return nil, err
	}

	return framework.LeaseExtend(ttl, maxTTL, b.System())(ctx, req, d)
}

type config struct {
	Host string `json:"host"`
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	host := d.Get("host").(string)
	if host == "" {
		return logical.ErrorResponse("no host provided"), nil
	}
	config := &config{
		Host:host,
	}
	entry, err := logical.StorageEntryJSON("/config", config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	raw, err := req.Storage.Get(ctx, "/config")
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	conf := &config{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	} else if conf == nil {
		return nil, nil
	} else {
		resp := &logical.Response{
			Data: map[string]interface{}{
				"host":    conf.Host,
			},
		}

		return resp, nil
	}
}

type role struct {
	Policies []string `json:"policies" structs:"policies" mapstructure:"policies"`
	PolicyNames []string `json:"policy_names" structs:"policy_names" mapstructure:"policy_names"`
	Roles []string `json:"roles" structs:"roles" mapstructure:"roles"`
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.l.RLock()
	defer b.l.RUnlock()

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

	b.l.Lock()
	defer b.l.Unlock()

	raw, err := req.Storage.Get(ctx, fmt.Sprintf("%s%s", "role/", strings.ToLower(name)))
	if err != nil {
		return nil, err
	}
	b.Logger().Info(fmt.Sprint(req.Operation))

	role := &role{}
	if raw == nil && req.Operation == logical.CreateOperation {
		return nil, fmt.Errorf("role entry not found during update operation")
	} else if raw == nil {
		if err := json.Unmarshal(raw.Value, role); err != nil {
			return nil, err
		}
	}

	if policiesRaw, ok := d.GetOk("policies"); ok {
		role.Policies = policyutil.ParsePolicies(policiesRaw)
	}

	if policyNames, ok := d.GetOk("policy_names"); ok {
		role.PolicyNames = policyNames.([]string)
	} else if req.Operation == logical.UpdateOperation {
		role.PolicyNames = d.Get("policy_names").([]string)
	}

	if roles, ok := d.GetOk("roles"); ok {
		role.Roles = roles.([]string)
	} else if req.Operation == logical.UpdateOperation {
		role.Roles = d.Get("roles").([]string)
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
	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

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
			"policies":			role.Policies,
			"policy_names":     role.PolicyNames,
			"roles":            role.Roles,
		},
	}

	return resp, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.l.Lock()
	defer b.l.Unlock()

	if err := req.Storage.Delete(ctx, "role/"+strings.ToLower(roleName)); err != nil {
		return nil, err
	}

	return nil, nil
}
