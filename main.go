package main

import (
	"log"
	vaultAPI "github.com/hashicorp/vault/api"
	"flag"
	"bufio"
	"os"
	"fmt"
)


func main() {

	var targetVaultAddr, vaultRootToken string
	flag.StringVar(&targetVaultAddr, "targetVaultAddr", "", "vault_addr for the target vault, like https://example2.com:8200")
	flag.StringVar(&vaultRootToken, "rootToken", "", "Token for targetVaultAddr - must have root privs")
	flag.Parse()

	vClient := getVaultClient(vaultRootToken, targetVaultAddr)

	//fmt.Printf("Getting token accessors from %s\n", targetVaultAddr)
	//confirm("Are you sure you want to continue? [y/n]")

	self, err := vClient.Auth().Token().LookupSelf()
	if err != nil {
		fmt.Printf("error looking up own token: %s\n", err)
		os.Exit(1)
	}
	selfAccessor := self.Data["accessor"].(string)


	result, _ := listAccessors(vClient)

	switch accessors := result.Data["keys"].(type) {
	case []interface{}:
		//fmt.Printf("got %T\n", accessors)
		for _, accessor := range accessors {
			//fmt.Println(i, accessor)
			details, err := inspectAccessor(vClient, accessor.(string))
			if (err != nil) {
				panic(err)
			}
			policies := details.Data["policies"]
			switch typedPolicies := policies.(type) {
			case []interface{}:
				for _, policy := range typedPolicies {
					//fmt.Printf(" %s ", policy.(string))
					if policy.(string) == "root" {
						if selfAccessor == accessor {
							fmt.Printf("Root accessor THIS IS YOU, revoke if you will with 'vault token-revoke -accessor %s'\n", accessor)
						} else {
							fmt.Printf("Root accessor, revoke with 'vault token-revoke -accessor %s'\n", accessor)
						}

					}
				}
			}

			//fmt.Printf("Accessor: %d %s: \n\t%v\t%v\n", i, accessor, policies, details)
		}
	default:
		fmt.Printf("I don't know how to handle %T\n", result.Data["keys"])
		os.Exit(2)
	}

	//targetVault.Auth().Token()
	// Get the list of accessors (through direct https query I guess)
	// Walk the list of accessors and gather/present info based on what they are.
}


// Simple confirmation prompt. return true on 'y'
func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt + ":")
	response, _ := reader.ReadString('\n')
	if (response != "y\n") {
		return false
	}
	return true
}


// Get vault object using token + vault_addr
func getVaultClient(token string, vaultAddr string) vaultAPI.Client {
	var err error
	var vClient      *vaultAPI.Client

	vaultCFG := *vaultAPI.DefaultConfig()

	vaultCFG.Address = vaultAddr

	vClient, err = vaultAPI.NewClient(&vaultCFG)
	if err != nil {
		log.Panic(err)
	}

	vClient.SetToken(token)

	return *vClient
}

func listAccessors(client vaultAPI.Client) (*vaultAPI.Secret, error) {
	request := client.NewRequest("LIST", "/v1/auth/token/accessors")

	resp, err := client.RawRequest(request)
	if (err != nil) {
		return nil, err
	}
	defer resp.Body.Close()

	return vaultAPI.ParseSecret(resp.Body)
}

func inspectAccessor(client vaultAPI.Client, accessor string)  (*vaultAPI.Secret, error) {
	request := client.NewRequest("POST", "/v1/auth/token/lookup-accessor")

	if err := request.SetJSONBody(map[string]interface{}{
		"accessor": accessor,
	}); err != nil {
		return nil, err
	}
	resp, err := client.RawRequest(request)
	if (err != nil) {
		return nil, err
	}

	defer resp.Body.Close()
	return vaultAPI.ParseSecret(resp.Body)
}
