# Vault Authentication plugin for Chef

## At the moment the README is lacking important information and should not be considered complete

# Supported sources:
    * Chef policy
    * Roles
    * SolR searches with cache
## Quick-start

### Setup
```
export TMPDIR=$(mktemp -d)
```

### Build the binary

```
go build -o $TMPDIR/plugin
```

### Starting Vault with plugins

Here's a simple line you can use to start a dev instance with plugins already catalogued
```
vault server -dev -dev-plugin-dir=$(realpath $TMPDIR) -dev-plugin-init -dev-root-token-id=devtoken -log-level=trace
```

Otherwise, use the regular way to catalog them
~~~

export SHA256=$(shasum -a 256 "$TMPDIR/plugin" | cut -d' ' -f1)
vault write sys/plugins/catalog/vault-auth-plugin-chef sha_256="${SHA256}" command="plugin"

vault auth enable -path="chef" -plugin-name="vault-auth-plugin-chef" plugin
~~~

### Configuration
#### Top level
~~~
vault write auth/chef/config host="http://chef-server.example.com"
~~~

#### Configure a policy
```
vault write auth/chef/policy/my-policy policies="default" period=86400
```

#### OPT: Add a search mapping
```
# Allowed staleness is an optionnal caching mechanism for big chef deployments

vault write auth/chef/search/recipes policies=openssh-secret search_query="recipes:openssh*" allowed_staleness=60
```

### Login !
~~~
vault write auth/chef/login node_name="node_name" private_key="private_key"
~~~

References:

* https://github.com/hashicorp/vault-auth-plugin-example
* https://www.hashicorp.com/blog/building-a-vault-secure-plugin
* https://www.vaultproject.io/docs/internals/plugins.html

