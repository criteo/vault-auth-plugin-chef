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

// Factory is a factory for a logical backend
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
	SearchStore *sync.Map
}

// Backend is the factory for our backend
func Backend(_ *logical.BackendConfig) *backend {
	var b backend

	b.SearchStore = &sync.Map{}
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
			pathRole(&b),
			pathPolicy(&b),
			pathSearch(&b),
		),
	}
	return &b
}
