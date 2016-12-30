
$(GOPATH)/bin/vault_token_lister: vault_token_lister.go
	go install

clean:
	go clean
	rm -f $(GOPATH)/bin/vault_token_lister
