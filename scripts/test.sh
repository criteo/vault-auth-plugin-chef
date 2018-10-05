#!/bin/bash
set -x
set -e

DIR=$(mktemp -d)

function poison()
{
	pkill vault
    rm -rf "$DIR"
}
export VAULT_ADDR=http://127.0.0.1:8200 && export VAULT_TOKEN=devtoken
go build -o "$DIR/vault-auth-chef-plugin" && vault server -dev -dev-plugin-dir="$DIR" -dev-plugin-init -dev-root-token-id=$VAULT_TOKEN -log-level=trace &
sleep 1
trap poison EXIT
vault auth enable -path chef-central -plugin-name=vault-auth-chef-plugin plugin
vault write auth/chef/config host="https://chef-server.example.com"
# Supposed node.example.com is a policy
vault write auth/chef/policy/example_policy period=500 policies=default
vault write auth/chef/login node_name=node.example.com private_key="$(cat node-key.pem)"