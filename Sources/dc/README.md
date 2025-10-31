# IBM Verify Digital Credentials SDK for iOS

The DC software development kit (SDK) provides functionality to support credential issurance and verifications in a mobile application.
 
## Getting started

### Overview
IBM Verify Identity Access enables businesses, governments, and individuals to issue, manage, and verify digital credentials with the Digital Credentials feature.
[IBM Verify Identity Access Digital Credentials configuration](https://www.ibm.com/docs/en/sva/11.0.0?topic=configuring-verify-identity-access-digital-credentials-configuration)

### Installation

[Swift Package Manager](https://swift.org/package-manager/) is used for automating the distribution of Swift code and is integrated into the `swift` compiler.  To depend on one or more of the components, you need to declare a dependency in your `Package.swift`:

```swift
dependencies: [
    .package(name: "IBM Verify", url: "https://github.com/ibm-verify/verify-mobile-ios.git", from: "3.0.11")
]
```

then in the `targets` section of the application/library, add one or more components to your `dependencies`, for example:

```swift
// Target for Swift 5.7
.target(name: "MyExampleApp", dependencies: [
    .product(name: "DC", package: "IBM Verify")
],
```

Alternatively, you can add the package manually.
1. Select your application project in the **Project Navigator** to display the configuration window.
2. Select your application project under the **PROJECT** heading
3. Select the **Swift Packages** tab.
4. Click on the `+` button.
5. Enter `https://github.com/ibm-verify/verify-mobile-ios.git` as the respository URL and follow the remaining steps selecting the components to add to your project.

### API documentation
The Digital Credentails SDK API can be reviewed [here](https://ibm-verify.github.io/ios/documentation/dc/).

### Importing the SDK

Add the following import statement to the `.swift` files you want to reference the Digital Credentails SDK.

```swift
import DC
```

## Usage

### Initializing a wallet

A wallet is the broker between a holder agent of a digital credential and other agents that may issue or request verification of a credential.

To initialize a wallet, your digital credentials service generates a QR code that contains specific endpoint information.  Ensure you include the
`Accept: image/png` and the `Authorization: Bearer <user_token>` headers.
```
GET http://<hostname>/diagency/v1.0/diagency/.well-known/agency-configuration
```

```swift
// Create an access token.
let oAuthProvider = OAuthProvider(clientId: "abc123")
let token = try await oAuthProvider.authorize(issuer: URL(string: "https://sdk.verifyaccess.ibm.com/oauth2/token")!, username: "user", password: "password")

// Value from QR code scan.
let qrScanResult = """
{
    "serviceBaseUrl": "https://sdk.verifyaccess.ibm.com/diagency",
    "oauthBaseUrl": "https://sdk.verifyaccess.ibm.com/oauth2"
}
"""

// Create the wallet provider.
let provider = WalletProvider(json: qrScanResult)

// Instaniate the wallet.
let wallet = try await provider.register(with: "John", clientId: "abc123", token: token, pushToken: "abc123")

// Get a list of credentials document types.
wallet.credentials.forEach { $0
   print($0.documentTypes)
}
```

#### Persisting the wallet
The wallet holds credentials, invitations, connections and agent information.  

> NOTE: Invitation data is not retrieved when the wallet is first initialized.

The `Wallet` structure supports `Codable` allowing the instance to be persisted to a storage model of your choosing. i.e SwiftData, File etc.  The following examples demonstrates using `JSONEncoder` and `JSONDecoder`.

##### Write wallet to file
```swift
if let data = try? JSONEncoder().encode(wallet) {
    let url = URL(fileURLWithPath: "wallet.json")
    do {
        try data.write(to: url)
    } 
    catch let error {
        print("Failed to write wallet: \(error.localizedDescription)")
    }
}
```

##### Read wallet from file
```swift
do {
    let url = URL(fileURLWithPath: "wallet.json")
    let data = try Data(contentsOf: url)
    let decoder = JSONDecoder()
    let wallet = try decoder.decode(Wallet.self, from: data)
}
catch let error {
        print("Failed to read wallet: \(error.localizedDescription)")
    }
```

### Accepting a credential

A credential is offered to a holder agent which can be then added to the wallet.  Interactions with the wallet are performed using the `WalletService`.  The following example demonstrates the flow to preview and accept a credential.

```swift
// Create a "WalletService" using the initialized wallet.
let service = WalletService(token: wallet.token.accessToken, 
    refreshUri: wallet.refreshUri, 
    baseUri: wallet.baseUri,
    clientId: wallet.clientId)

// Add the "WalletServiceDelegate" to handle WalletServiceDelegate(service:, didAcceptCredential:) event to add the credential to the wallet.
service.delegate = self
                
// Value from QR code scan.
let qrScanResult = "https://sdk.verifyaccess.ibm.com/diagency/a2a/v1/messages/eec19c85-d8e7-4694-8520-19762b0e76f7/invitation?id=001988fc-df4c-482e-9438-3313b91d5318"
   
// Use the "preview.jsonRepresentation" to display how a credential should look in the UI.
let preview = try await service.previewInvitation(using: qrScanResult)

// Accept the credential.
if let preview = preview as? CredentialPreviewInfo {
    try await service.processCredential(with: preview)
}

// WalletServiceDelegate
func walletService(service: WalletService, didAcceptCredential credential: Credential) {
    wallet.credentials.append(credential)
}
```
### Verifying a credential

An agent can initiate a proof request via an invitation to verify a credential in a wallet.  The claims that are requested by the verifier are first generated, then shared for the verifier to validation.  Interactions with the wallet are performed using the `WalletService`.  The following example demonstrates the flow to preview an verification invitation, generate the claims and share with the verifier:

```swift
// Create a "WalletService" using the initialized wallet.
let service = WalletService(token: wallet.token.accessToken, 
    refreshUri: wallet.refreshUri, 
    baseUri: wallet.baseUri,
    clientId: wallet.clientId)

// Add the "WalletServiceDelegate" to handle the add verification event.
service.delegate = self

// Use the "preview.name" and "preview.purpose" to display how should look in the UI.
let preview = try await service.previewInvitation(using: qrScanResult)

// Generate the claims to submit.  Handle the result of this call in the WalletServiceDelegate(service:, didGenerateProof:)
if let preview = preview as? VerificationPreviewInfo {
    try await service.processProofRequest(with: preview)
}

// Share the claims with the verifier. Handle the result of this call in the WalletServiceDelegate(service:, didVerifyCredential:)
if let preview = preview as? VerificationPreviewInfo {
    try await service.processProofRequest(with: preview, action: .share)
}

// WalletServiceDelegate

func walletService(service: WalletService, didVerifyCredential verification: VerificationInfo) {
        print(verification)
}
    
func walletService(service: WalletService, didGenerateProof verification: VerificationInfo) {
    // Use the verification display detailed information about the proof request.
        print(verification)        
}
```

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
