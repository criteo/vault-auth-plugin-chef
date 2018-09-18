# Vault Authentication plufin for Chef

This repository contain the source code of the vault authentication plugin for chef.

Build the project:

~~~
go build
~~~

Copy the plugin into the vault plugin directory:

~~~
cp vault-auth-plugin-chef /opt/vault/plugin_directory
~~~

Add the plug-in to the vault server
~~~
export VAULT_ADDR="http://127.0.0.1:8200"

export SHA256=$(shasum -a 256 "/opt/vault/plugin_directory/vault-auth-plugin-chef" | cut -d' ' -f1)

vault write sys/plugins/catalog/vault-auth-plugin-chef sha_256="${SHA256}" command="vault-auth-plugin-chef"

vault auth-enable -path="chef" -plugin-name="vault-auth-plugin-chef" plugin
~~~

Configure the chef server
~~~
vault write auth/chef/config host="http://chef-server.com"
~~~

Configure a role
~~~
vault write auth/chef/role/default policies="default" policy_names="chef_policy" roles="chef_role" ttl=259200 max_ttl=777600 period=2592000
~~~

How to login using the plugin
~~~
vault write auth/chef/login node_name="node_name" private_key="private_key"
~~~


References:

* https://github.com/hashicorp/vault-auth-plugin-example
* https://www.hashicorp.com/blog/building-a-vault-secure-plugin
* https://www.vaultproject.io/docs/internals/plugins.html
