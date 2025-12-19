# IBM Verify Adaptive SDK for iOS

The Adaptive software development kit (SDK) provides device assessment. Based on cloud risk policies, authentication and authorization challenges can be evaluated.


## Example
An [example](../../Examples/adaptive) application is available for the Adaptive SDK.

## Getting started

### Prerequisites

- Install and configure the
[Proxy SDK](https://github.com/ibm-verify/adaptive-proxy-sdk-javascript) on a Node server by running `npm install adaptive-proxy-sdk`

- Generate and download the Trusteer SDK via IBM Verify admin portal for the application.

> See [On-board a native application](https://docs.verify.ibm.com/verify/docs/on-boarding-a-native-application)

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
    .product(name: "Adaptive", package: "IBM Verify")
],
```

Alternatively, you can add the package manually.
1. Select your application project in the **Project Navigator** to display the configuration window.
2. Select your application project under the **PROJECT** heading
3. Select the **Swift Packages** tab.
4. Click on the `+` button.
5. Enter `https://github.com/ibm-verify/verify-sdk-ios.git` as the respository URL and follow the remaining steps selecting the components to add to your project.


### API documentation
The Adaptive component API can be reviewed [here](https://ibm-verify.github.io/ios/documentation/adaptive/).

### Importing the SDK

Add the following import statement to the `.swift` files you wish to reference the Verify Adaptive SDK.

```swift
import Adaptive
```

### Trusteer configuration settings

To start a device collection analysis, you will need to initialise a `TrusteerCollectionService` structure.  This structure is part of the Trusteer zip you can obtain via your tenant configuration  or via the IBM Verify Developer Portal.  Also included in the Trusteer zip will be your `vendorId`, `clientId` and `clientKey`. 


## Usage

### Start the collection service

To start the collection, an instance `AdaptiveCollectionService` is assigned to  `AdaptiveContext.shared.collectionService`.

```swift
// Initial a new instance of TrusteerCollectionService with client info provided in the Trusteer zip.
let trusteerCollection = TrusteerCollectionService(using: "domain.com", clientId: "com.domaim.app", clientKey:  "YMAQAABNFUWS2LKCIVDUSTRAKBKU..."
AdaptiveContext.shared.collectionService = trusteerCollection
try? AdaptiveContext.shared.start()
```

### Stop the collection service

```swift
// Stop the collection
try? AdaptiveContext.shared.stop()
```

### Implementing AdaptiveDelegate

The `AdaptiveDelegate` protocol needs to be implemented in order to expose the `assessment`, `generate` and `evaluate` functions.

```swift
// Implementing the `AdaptiveDelegate` protocol as a singleton
class MyAdaptive: AdaptiveDelegate {
  static let shared = Adaptive()
  private init() {}

  // Implement the `assessment` function
  func assessment(with sessionId: String, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void) {
    // Send a request to the server to perform risk assessment for the given session ID using the Proxy SDK.
  }

  // Implement the `generate` function
  func generate(with factor: FactorGenerationInfo, completion: @escaping (Result<Void, Error>) -> Void) {
    // Send a request to the server to generate a verification for the given `FactorGenerationInfo` using the Proxy SDK.
  }

  // Implement the `evaluate` function
  func evaluate(using response: FactorEvaluation, evaluationContext: String, completion: @escaping (Result<AdaptiveResult, Error>) -> Void) {
    // Send a request to the server to evaluate a verification for the given `FactorEvaluation` using the Proxy SDK.
  }
}
```

### Perform a risk assessment

The purpose of the `assessment` function is to initiate a risk assessment via the [Proxy SDK](https://github.com/ibm-verify/adaptive-proxy-sdk-javascript). The implementation of the `assessment` function should send a request to the Proxy SDK.

Upon receiving the request, the server should call the Proxy SDK's
[`assess`](https://github.com/ibm-verify/adaptive-proxy-sdk-javascript/tree/develop#assess-a-policy) method, and respond accordingly.

Once a successful response is received, it can be classified into one of `AllowAssessmentResult`, `DenyAssessmentResult`, or `RequiresAssessmentResult` structures, to be passed in the `completion` function.                             

```swift
  // Perform risk assessment
  MyAdaptive.shared.assessment(with: AdaptiveContext.shared.sessionId, evaluationContext: "login") { result in
    switch result {
    case .success(let requiresResult as RequiresAssessmentResult):
      // `requires` result
    case .success(let allowResult as AllowAssessmentResult):
      // `allow` result
    case .success(_):
      // `deny` result
    case .failure(let error):
      // Error during assessment
      print(error.localizedDescription)
    }
  }
```

### Perform a factor generation

The `generate` function is to generate a `FactorType` verification via
the [Proxy SDK](https://github.com/ibm-verify/adaptive-proxy-sdk-javascript).

The implementation of this function should send a request to a server using the Proxy SDK. Upon receiving the request, the server should call the Proxy SDK's [`generateEmailOTP`](https://github.com/ibm-verify/adaptive-proxy-sdk-javascript/tree/develop#generate-an-email-otp-verification) or [`generateSMSOTP`](https://github.com/ibm-verify/adaptive-proxy-sdk-javascript/tree/develop#generate-an-sms-otp-verification) methods. The method to call should correspond to a `FactorGenerationInfo` type of the `factor` property. Typically, the server will not respond after generating these verifications.

The currently supported `FactorType` for generation are `.emailOTP`
and `.smsOTP`.

```swift
  // Create a `FactorGenerationInfo` instance
  // (The `transactionId` is received from the `assessment` function on a `requires` status.)
  let generationInfo = FactorGenerationInfo(transactionId: transactionId, factor: .smsOTP)

  // Generate verification
  MyAdaptive.shared.generate(with: generation) { (result) in
    switch result {
    case .success():
      // SMS OTP successfully sent.
    case .failure(let error):
      // Error during generation
      print(error.localizedDescription)
    }
  }
```

### Perform a factor evaluation

The implementation of this function should send a request to a server using the Proxy SDK. Upon receiving the request, the server should call the Proxy SDK's [`evaluateUsernamePassword`](https://github.com/ibm-verify/adaptive-proxy-sdk-javascript/tree/develop#evaluate-a-username-password-verification)
or [`evaluateOTP`](https://github.com/ibm-verify/adaptive-proxy-sdk-javascript/tree/develop#evaluate-an-otp-verification)
methods, and respond accordingly. The method to call should depend on the instance of `FactorEvaluation` (either
`UsernamePasswordEvaluation` or
`OneTimePasscodeEvaluation`.

Once a successful response is received, it can be classified into one of `AllowAssessmentResult`, `DenyAssessmentResult` or
`RequiresAssessmentResult` structures, to be passed in the `completion` function.

```swift
  // Create a `FactorEvaluation` instance
  // (The `transactionId` is received from the `assessment` function on a `requires` status.)
  let usernamePasswordEvaluation = UsernamePasswordEvaluation(transactionId, username: "username", password: "password")

  // Evaluate a factor verification
  MyAdaptive.shared.evaluate(using: usernamePasswordEvaluation, evaluationContext: "login") { (result) in
    switch result {
    case .success(let allowResult as AllowAssessmentResult):
      // `allow` result
    case .success(_):
      // `deny` result
    case .failure(let error):
      // Error during evaluation
      print(error.localizedDescription)
    }
  }
```

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
