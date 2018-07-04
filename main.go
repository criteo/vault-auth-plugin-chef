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
	Pattern: "config",
	Fields: map[string]*framework.FieldSchema{
		"host": {
			Type: framework.TypeString,
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
		},
		"private_key": {
			Type: framework.TypeString,
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
			},
			"policies": {
				Type: framework.TypeStringSlice,
			},
			"policy_names": {
				Type: framework.TypeStringSlice,
			},
			"roles": {
				Type: framework.TypeStringSlice,
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
			},
			"max_ttl": {
				Type: framework.TypeDurationSecond,
			},
			"period": {
				Type: framework.TypeDurationSecond,
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
