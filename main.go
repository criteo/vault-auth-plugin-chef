package main

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/logical/plugin"
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
	sync.RWMutex
	rolesMap map[string][]*role
	policiesMap map[string][]*role
}

func Backend(_ *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
			SealWrapStorage: []string{"config"},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(&b),
				pathLogin(&b),
			},
			pathsRole(&b),
		),
		}
	b.policiesMap = make(map[string][]*role)
	b.rolesMap = make(map[string][]*role)
	return &b
}

func pathConfig(b *backend) *framework.Path {
     return &framework.Path{
	Pattern: "config$",
	Fields: map[string]*framework.FieldSchema{
		"host": {
			Type: framework.TypeString,
			Description: "Host must be a host string, a host:port pair, or a URL to the base of the Chef server.",
		},
	},
	Callbacks: map[logical.Operation]framework.OperationFunc{
		logical.UpdateOperation: b.pathConfigWrite,
		logical.CreateOperation: b.pathConfigWrite,
		logical.ReadOperation:   b.pathConfigRead,
	},
     }
}
func pathLogin(b *backend) *framework.Path {
     return &framework.Path{
	Pattern: "login",
	Fields: map[string]*framework.FieldSchema{
		"node_name": {
			Type: framework.TypeString,
			Description: "The node name, can be often found at /etc/chef/client.rb.",
		},
		"private_key": {
			Type: framework.TypeString,
			Description: "The private key, can be often found at /etc/chef/client.pem.",
		},
	},
	Callbacks: map[logical.Operation]framework.OperationFunc{
		logical.UpdateOperation: b.pathAuthLogin,
	},
    }
}

func pathsRole(b *backend) []*framework.Path {
     return []*framework.Path{
     	    &framework.Path{
		Pattern: "role/?",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
     	    },
	    &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type: framework.TypeString,
				Description: "Name of the role.",
			},
			"policies": {
				Type: framework.TypeStringSlice,
				Description: "Vault policies that will be attached to the token.",
			},
			"policy_names": {
				Type: framework.TypeStringSlice,
				Description: "Chef policies that will match against the informations returned by the chef server.",
			},
			"roles": {
				Type: framework.TypeStringSlice,
				Description: "Chef roles that will match against the informations returned by the chef server.",
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: "Initial TTL to associate with the token. Token renewals may be able to extend beyond this value, " +
					"depending on the configured maximumTTLs. This is specified as a numeric string with suffix like 30s or 5m",
			},
			"max_ttl": {
				Type: framework.TypeDurationSecond,
				Description: "Maximum lifetime for the token. Unlike normal TTLs, the maximum TTL is a hard limit and cannot " +
					"be exceeded. This is specified as a numeric string with suffix like 30s or 5m.",
			},
			"period": {
				Type: framework.TypeDurationSecond,
				Description: "If specified, every renewal will use the given period. Periodic tokens do not expire. " +
					"This is specified as a numeric string with suffix like 30s or 5m.",
			},
		},
		ExistenceCheck: b.pathRoleExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathRoleCreateUpdate,
			logical.UpdateOperation: b.pathRoleCreateUpdate,
			logical.ReadOperation:   b.pathRoleRead,
			logical.DeleteOperation: b.pathRoleDelete,
		},
	  },
     }
}
