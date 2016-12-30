# Hashicorp Vault Token Lister

This tiny tool is built to walk the token accessors in a [Hashicorp Vault](https://www.vaultproject.io/) and use them to access the details and policies for each case, normally to allow (manual) revocation using the accessor.

It was written as a way to detect all root-level tokens so they could be revoked per [best practices suggested in vault manual](https://www.vaultproject.io/docs/concepts/tokens.html) (see "root tokens").

## Build:

Just run "make" and it will install into $GOPATH/bin

## Usage:
````
    vault_token_lister -targetVaultAddr=https://example.com:8200 -rootToken=someroot-7644-a9aa 
    vault_token_lister -targetVaultAddr=https://example.com:8200 -rootToken=someroot-7644-a9aa -policy=root
    vault_token_lister -targetVaultAddr=https://example.com:8200 -rootToken=someroot-7644-a9aa -policy=somepolicy
```
