package main

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

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

