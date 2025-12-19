# IBM Verify FIDO2™ SDK for iOS

The FIDO2 software development kit (SDK) is a native implementation of attestation and assertion ceremonies.  Essentially providing the equivalent
of WebAuthn's `navigator.credentials.create()` and `navigator.credentials.get()` for native mobile apps.  The FIDO2 SDK supports custom certificate attestation and authenticator extensions.


## Example
An [example](../../Examples/fido2) application is available for the FIDO2 SDK.


## Getting started

### Installation

[Swift Package Manager](https://swift.org/package-manager/) is used for automating the distribution of Swift code and is integrated into the `swift` compiler.  To depend on one or more of the components, you need to declare a dependency in your `Package.swift`:

```swift
dependencies: [
    .package(name: "IBM Verify", url: "https://github.com/ibm-verify/verify-sdk-ios.git", from: "3.0.12")
]
```

then in the `targets` section of the application/library, add one or more components to your `dependencies`, for example:

```swift
// Target for Swift 6.0
.target(name: "MyExampleApp", dependencies: [
    .product(name: "FIDO2", package: "IBM Verify")
],
```

Alternatively, you can add the package manually.
1. Select your application project in the **Project Navigator** to display the configuration window.
2. Select your application project under the **PROJECT** heading
3. Select the **Swift Packages** tab.
4. Click on the `+` button.
5. Enter `https://github.com/ibm-verify/verify-sdk-ios.git` as the respository URL and follow the remaining steps selecting the components to add to your project.

### API documentation
The FIDO2 SDK API can be reviewed [here](https://ibm-verify.github.io/ios/documentation/fido2/).

### Importing the SDK

Add the following import statement to the `.swift` files you wish to reference the FIDO2 SDK.

```swift
import FIDO2
```

## Usage

### Get attestation options

To get the attestation options, perform a HTTPS request to a relying party endpoint  `POST <server>/attestation/options`

```swift
// Create the request
let url = URL(string: "https://www.example.com/attestation/options")!
let request = URLRequest(url: url)
request.httpMethod = "POST"
request.setValue("Bearer ABC123", forHTTPHeaderField: "Authorization")

// Fetch the attestation options
URLSession.shared.dataTask(with: request) { data, response, error in
    guard let data = data else {
        return
    }
    
    guard let options = try? JSONDecoder().decode(PublicKeyCredentialCreationOptions.self, from: data) else {
        return
    }

    // Handle the options result
    print(options)
}.resume()
```

### Create an attestation request

Create a attestation request using the following code snippet:

```swift
let options = // PublicKeyCredentialCreationOptions from previous attestation options response

// Use the aaguid for the make and model of the authenticator. A relying party may use this to infer additional properties.
let aaguid = UUID(uuidString: "6dc9f22d-2c0a-4461-b878-de61e159ec61")!

// Attempt to generate the public key credential with a private key attestation.
let provider = PublicKeyCredentialProvider()

// Ensure you implement PublicKeyCredentialDelegate to handle the completed request.
provider.delegate = self
provider.createCredentialAttestationRequest(aaguid, statementProvider: SelfAttestation(aaguid), options: options)
```

To get the value of the result, see [Responding to the attestation and assertion requests](#Responding-to-the-attestation-and-assertion-requests).


### Get assertion options

To get assertion options, perform a HTTPS request to a relying party endpoint `POST <server>/assertion/options`

```swift
// Create the request
let url = URL(string: "https://www.example.com/assertion/options")!
let request = URLRequest(url: url)
request.httpMethod = "POST"
request.setValue("Bearer ABC123", forHTTPHeaderField: "Authorization")

// Fetch the assertion options
URLSession.shared.dataTask(with: request) { data, response, error in
    guard let data = data else {
        return
    }
    
    guard let options = try? JSONDecoder().decode(PublicKeyCredentialRequestOptions.self, from: data) else {
        return
    }

    // Handle the options result
    print(options)
}.resume()
```



### Create an assertion request

Create a assertion request using the following code snippet:

```swift
let options = // PublicKeyCredentialRequestOptions from previous assertion options response

// Attempt to generate the public key credential with a private key assertion.
let provider = PublicKeyCredentialProvider()

// Ensure you implement PublicKeyCredentialDelegate to get the callbacks.
provider.delegate = self
provider.createCredentialAssertionRequest(options: options)
```
To get the value of the result, see [Responding to the attestation and assertion requests](#Responding-to-the-attestation-and-assertion-requests).



### Responding to the attestation and assertion requests

The `PublicKeyCredentialDelegate` provides information about the outcome of an attestation or assertion request. Adopt this protocol to determine how to react and process success or errors.

For an attestation result, update the user's account by performing a HTTPS request to a relying party endpoint `POST <server>/attestation/result`

```swift
extension ViewController: PublicKeyCredentialDelegate {
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithError error: Error) {
        // Error during attestation
    }

    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAttestation result: PublicKeyCredential<AuthenticatorAttestationResponse>) {
        // Convert the attestation response to JSON
        guard let data = try? JSONEncoder().encode(result) else {
            return
        }

        // Create the request
        let url = URL(string: "https://www.example.com/attestation/result")!
        let request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer ABC123", forHTTPHeaderField: "Authorization")
        request.httpBody = data

        // Create the authenticator
        URLSession.shared.dataTask(with: request) { data, response, error in
            // Handle the result.
             guard let data = data else {
                return
            }

            print(String(decoding: data, as: UTF8.self))
        }.resume()
    }
}
```


For an assertion result, you can validate the assertion by making a HTTPS request to a relying party endpoint `POST <server>/assertion/result`

```swift
extension ViewController: PublicKeyCredentialDelegate {
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithError error: Error) {
        // Error during assertion
    }
    
    func publicKeyCredential(provider: PublicKeyCredentialProvider, didCompleteWithAssertion result: PublicKeyCredential<AuthenticatorAssertionResponse>) {
        // Convert the assertion response to JSON
        guard let data = try? JSONEncoder().encode(result) else {
            return
        }

        // Create the request
        let url = URL(string: "https://www.example.com/assertion/result")!
        let request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer ABC123", forHTTPHeaderField: "Authorization")
        request.httpBody = data

        // Assert the authenticator
        URLSession.shared.dataTask(with: request) { data, response, error in
            // Handle the result.
            guard let data = data else {
                return
            }
        }.resume()
    }
}
```

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
<br/><br/>
FIDO™ and FIDO2™  are  trademarks (registered in numerous countries) of FIDO Alliance, Inc. 
