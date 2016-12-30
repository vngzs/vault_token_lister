// Simple tool to walk all vault accessors and display those associated
// with a particular policy, 'root' by default.
// vault_token_lister -targetVaultAddr=https://example.com:8200 -rootToken=someroot-7644-a9aa

package main

import (
	"log"
	vaultAPI "github.com/hashicorp/vault/api"
	"flag"
	"os"
	"fmt"
)

func main() {

	var targetVaultAddr, vaultRootToken, policy string
	flag.StringVar(&targetVaultAddr, "targetVaultAddr", "", "vault_addr for the target vault, like https://example2.com:8200")
	flag.StringVar(&vaultRootToken, "rootToken", "", "Token for targetVaultAddr - must have root privs")
	flag.StringVar(&policy, "policy", "root", "Name of policy we're looking for, by default 'root'")
	flag.Parse()

	vClient := getVaultClient(vaultRootToken, targetVaultAddr)

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
			details, err := vClient.Auth().Token().LookupAccessor(accessor.(string))
			if (err != nil) {
				panic(err)
			}
			policies := details.Data["policies"]
			displayName := details.Data["display_name"].(string)
			switch typedPolicies := policies.(type) {
			case []interface{}:
				for _, p := range typedPolicies {
					//fmt.Printf(" %s ", policy.(string))
					if p.(string) == policy {
						output := fmt.Sprintf("%s accessor displayName=%s: revoke if you will with 'vault token-revoke -accessor %s'\n", policy, displayName, accessor)
						if selfAccessor == accessor {
							output = "THIS IS YOU, " + output
						}
						fmt.Println(output)

					}
				}
			}

			//fmt.Printf("Accessor: %s: \n\t%v\t%v\n", accessor, policies, details)
		}
	default:
		fmt.Printf("I don't know how to handle %T\n", result.Data["keys"])
		os.Exit(2)
	}

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

// Use API to get list of all token accessors
func listAccessors(client vaultAPI.Client) (*vaultAPI.Secret, error) {
	request := client.NewRequest("LIST", "/v1/auth/token/accessors")

	resp, err := client.RawRequest(request)
	if (err != nil) {
		return nil, err
	}
	defer resp.Body.Close()

	return vaultAPI.ParseSecret(resp.Body)
}
