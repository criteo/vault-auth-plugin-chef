package main

import (
	"context"
	"encoding/json"

	"fmt"

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
		Host: host,
	}
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error while creating config entry : %s", err)), err
	}

	b.Lock()
	defer b.Unlock()

	if err := req.Storage.Put(ctx, entry); err != nil {
		b.Logger().Error("error occured while saving chef host config: %s", err)
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.RLock()
	defer b.RUnlock()

	raw, err := req.Storage.Get(ctx, "config")
	if err != nil {
		b.Logger().Error("error occured while fetching chef host config: %s", err)
		return logical.ErrorResponse(fmt.Sprintf("Error while fetching config : %s", err)), err
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
				"host": conf.Host,
			},
		}

		return resp, nil
	}
}
