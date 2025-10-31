# IBM Verify Authentication SDK for iOS

The Authentication software development kit (SDK) enables applications to obtain limited access to an HTTP service by orchestrating an approval interaction between the resource owner and the HTTP service.


## Example
An [example](../../Examples/authentication) application is available for the Authentication SDK

## Getting started

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
    .product(name: "Authentication", package: "IBM Verify")
],
```

Alternatively, you can add the package manually.
1. Select your application project in the **Project Navigator** to display the configuration window.
2. Select your application project under the **PROJECT** heading
3. Select the **Swift Packages** tab.
4. Click on the `+` button.
5. Enter `https://github.com/ibm-verify/verify-mobile-ios.git` as the respository URL and follow the remaining steps selecting the components to add to your project.

### API documentation
The Authentication SDK API can be reviewed [here](https://ibm-verify.github.io/ios/documentation/authentication/).

### Importing the SDK

Add the following import statement to the `.swift` files you want to reference the Authentication SDK.

```swift
import Authentication
```

## Usage

### Getting OpenId Configuration Metadata

Discover the authorization service configuration from a compliant OpenID Connect endpoint.

```swift
let url = URL(string: "https://www.example.com/.well-known/openid-configuration")!

let result = try await OAuthProvider.discover(issuer: url) { result in
print(result)
```

### Authorization Code Flow (AZN)

Authorization code flow is obtained by using an authorization server as an intermediary between the client and resource owner.  The code can later be exchanged for an access token and refresh token.  Refer to [Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) for more information.
        
```swift
import Authentication
import AuthenticationServices 

// The view controller to start user authentication.
class SigninViewController: UIViewController {
    let issuerUrl = URL(string: "https://www.example.com/authorize")!
    let tokenURL = URL(string: "https://www.example.com/token")!
    let redirectUrl = URL(string: "verifysdk://auth/callback")!

    func onSigninClick() {
        let provider = OAuthProvider(clientId: "a1b2c3d4")
        provider.delegate = self
        
        // Pass additional options like state and preserve the browser session if required.
        provider.authorizeWithBrowser(issuer: issuerURL,
            redirectUrl: self.redirectURL,
            presentingViewController: self)
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding
extension SigninViewController: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
}

// MARK: - OAuthProviderDelegate
extension SigninViewController: OAuthProviderDelegate {
    func oauthProvider(provider: OAuthProvider, didCompleteWithError error: Error) {
        print(error.localizedDescription)
    }

    @MainActor
    func oauthProvider(provider: OAuthProvider, didCompleteWithCode result: (code: String, state: String?)) {
        
        // Exchange the authorization code for an access token.
        Task {
            do {
                let result = try await provider.authorize(issuer: tokenURL!, redirectUrl: self.redirectURL, authorizationCode: result.code)
                print("save \(token)")
            }
            catch let error {
                print("error \(error.localizedDescription)")
            }
        }
    }
}
```

### Authorization Code Flow (AZN) with PKCE

PKCE enhances the authorization code flow by introducing a secret created by the calling application that can be verified by the authorization server.  The secret, called the Code Verifier is hashed by the calling application into a Code Challenge; it is this value that is send to the authorization server.  A malicious attacker can only intercept the Authorization Code, but cannot exchange it for an access token without the Code Verifier.  The code can later be exchanged for an access token and refresh token.  Refer to [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636) for more information.
        
```swift
import Authentication
import AuthenticationServices 

// The view controller to start user authentication.
class SigninViewController: UIViewController {
    let issuerUrl = URL(string: "https://www.example.com/authorize")!
    let tokenURL = URL(string: "https://www.example.com/token")!
    let redirectUrl = URL(string: "verifysdk://auth/callback")!
    var codeVerifier: String? = nil
    var codeChallenge: String? = nil

    func onSigninClick() {
        let provider = OAuthProvider(clientId: "a1b2c3d4")
        provider.delegate = self

        // Generate the code verifier and challenge
        self.codeVerifier = PKCE.generateCodeVerifier()
        self.codeChallenge = PKCE.generateCodeChallenge(from: self.codeVerifier!)
        
        // Pass additional options like state and preserve the browser session if required.
        provider.authorizeWithBrowser(issuer: issuerURL,
            redirectUrl: self.redirectURL,
            presentingViewController: self,
            codeChallenge: self.codeChallenge,
            method: .S256)
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding
extension SigninViewController: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
}

// MARK: - OAuthProviderDelegate
extension SigninViewController: OAuthProviderDelegate {
    func oauthProvider(provider: OAuthProvider, didCompleteWithError error: Error) {
        print(error.localizedDescription)
    }

    @MainActor
    func oauthProvider(provider: OAuthProvider, didCompleteWithCode result: (code: String, state: String?)) {
        
        // Exchange the authorization code for an access token with the code verifier.
        Task {
            do {
                let result = try await provider.authorize(issuer: tokenURL!, redirectUrl: self.redirectURL, authorizationCode: result.code, codeVerifier: self.codeVerifier) 
                print("save \(token)")
            }
            catch let error {
                print("error \(error.localizedDescription)")
            }
        }
    }
}
```

### Basic Resource Owner Password Credentials (ROPC) grant

Obtaining a token based on a username and password.

```swift
let url = URL(string: "https://www.example.com/token")!

// Optionally add additional parameters to the request.
let provider = OAuthProvider(clientId: "a1b2c3", additionalParameters: ["pet": "dog", "food": "pizza"])

// Pass in optional scopes.
let result = try await provider.authorize(issuer: url, username: "testuser", password: "password", scope: ["name", "age"])
print(result)
```

### Refreshing a Token

Refresh tokens are issued to the client by the authorization server and are used to obtain a new access token when the current access token becomes invalid or expires, or to obtain additional access tokens with identical or narrower scope.

```swift
let url = URL(string: "https://www.example.com/token")!

// Optionally add additional parameters to the request.
let provider = OAuthProvider(clientId: "a1b2c3")

// Where `token` was previously obtained through an AZN code or ROPC flow.
let result = try await provider.refresh(issuer: url, refreshToken: token.refreshToken!, scope: ["name"])
print(result)
```

### Decoding the ID Token Claims
The ID token is an artifact that proves that the user has been authenticated introduced by [OpenID Connect (OIDC)](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).  The ID token is obtained when `openid` is part of the scope in your authorization request.

The ID token is represented as a sequence of URL-safe parts separated by period ('.') characters.  Each part contains a base64url encoded string, for example:

`{header}.{claims}.{signature}`

```swift
extension String {
    public var base64UrlEncodedStringWithPadding: String {
        var value = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        if value.count % 4 > 0 {
            value.append(String(repeating: "=", count: 4 - value.count % 4))
        }
        
        return value
    }
}

let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

// CLaims is the second element of data in the string.
let claims = jwt.components(separatedBy: ".")[1]

if let data = Data(base64Encoded: claims.base64UrlEncodedStringWithPadding), let dict = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] {
    print(dict)
}
```

NOTE: Best practice is to validate the claims against the signature before relying on them for other verifications. 3rd party libraries like [SwiftJWT](https://github.com/Kitura/Swift-JWT) can provide the verification and decoding of the ID token.


## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
