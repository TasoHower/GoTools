package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	coboWaas2 "github.com/CoboGlobal/cobo-waas2-go-sdk/cobo_waas2"
	"github.com/CoboGlobal/cobo-waas2-go-sdk/cobo_waas2/crypto"
)

func main() {

	// Specify the wallet type as Custodial Wallet.
	walletType := coboWaas2.WalletType("Custodial")
	// walletType, err := coboWaas2.NewWalletTypeFromValue("Custodial")

	// Specify the wallet sub-type as Asset Wallet.
	walletSubtype := coboWaas2.WalletSubtype("Asset")
	// walletSubType, err := coboWaas2.NewWalletSubtypeFromValue("Asset")

	// Use pagination parameters if needed
	limit := int32(10)
	before := ""
	after := ""

	configuration := coboWaas2.NewConfiguration()
	apiClient := coboWaas2.NewAPIClient(configuration)
	ctx := context.Background()
	// Select the environment that you use and comment out the other line of code.
	ctx = context.WithValue(ctx, coboWaas2.ContextEnv, coboWaas2.DevEnv)
	// ctx = context.WithValue(ctx, coboWaas2.ContextEnv, coboWaas2.ProdEnv)
	ctx = context.WithValue(ctx, coboWaas2.ContextPortalSigner, crypto.Ed25519Signer{
		// Replace `<YOUR_PRIVATE_KEY>` with your own private key.
		Secret: "7aeb001bf14b6293edb7ca9479783f6bcf370b2ba41496be24f7846ddc5a80cd",
	})
	// Call the List supported chains operation.
	req := apiClient.WalletsAPI.ListSupportedChains(ctx).WalletType(walletType).WalletSubtype(walletSubtype)
	if limit > 0 {
		req = req.Limit(limit)
	}
	if before != "" {
		req = req.Before(before)
	}
	if after != "" {
		req = req.After(after)
	}
	resp, r, err := req.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `WalletsAPI.ListSupportedChains``: %v\n", err)
		if apiErr, ok := err.(*coboWaas2.GenericOpenAPIError); ok {
			fmt.Fprintf(os.Stderr, "Error response: %s\n", string(apiErr.Body()))
		}
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// Handle response from `ListSupportedChains`.
	respJson, _ := json.MarshalIndent(resp, "", " ")
	fmt.Fprintf(os.Stdout, "Response from `WalletsAPI.ListSupportedChains`: \n%s", string(respJson))
}
