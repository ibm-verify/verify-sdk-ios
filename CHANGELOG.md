Note: This is in reverse chronological order, so newer entries are added to the top.

# v3.1.5
12 June 2026

### IBM Verify MFA SDK for iOS
* Refactored pending transaction lookup and nil handling
* Handle invalid content-type for `OnPremiseRegistrationProvider` signature enrollments

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>

# v3.1.4
4 June 2026

### IBM Verify MFA SDK for iOS
* Rosolves an issue during `OnPremiseRegistrationProvider.finalize()` with self-signed certificate enabled

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version
* Use ephemeral sessions for network operations

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>

# v3.1.3
4 June 2026

### IBM Verify MFA SDK for iOS
* Reinstate support for OTP registration during MFA QR code scanning
* Adds warning when trying to initially connect to a account provider that is  using self-signed certificates

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>

# v3.1.2
30 May 2026

### IBM Verify MFA SDK for iOS
* Fixes issue when service_name not provided in OnPremiseRegistrationProvider MFA registration.
* Fixes the `refreshUri` for `OnPremiseRegistrationProvider` MFA registration.
* Normalise "fingerprint" to "biometrics" for signature enrolments created using IBM Verify v2 SDK.
* Adds "Not available" as the `OnPremiseAuthenticator.displayName` when omitted from `OnPremiseRegistrationProvider.initiate()` and not present in the access token during on-premise MFA registration.
* Use ephemeral sessions for network operations

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version
* Use ephemeral sessions for network operations

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>

# v3.1.1
22 April 2026

### IBM Verify MFA SDK for iOS
* Fixes issue when service_name not provided in OnPremiseRegistrationProvider MFA registration.
* Fixes the `refreshUri` for `OnPremiseRegistrationProvider` MFA registration.
* Normalise "fingerprint" to "biometrics" for signature enrolments created using IBM Verify v2 SDK.
* Adds "Not available" as the `OnPremiseAuthenticator.displayName` when omitted from `OnPremiseRegistrationProvider.initiate()` and not present in the access token during on-premise MFA registration.
* Use ephemeral sessions for network operations

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version
* Use ephemeral sessions for network operations

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>


# v3.1.0
21 April 2026
### IBM Verify DC SDK for iOS
* Remove support for digital credentials. Refer to https://github.com/IBM-Verify/verify-mobile-dc-wallet-ios

### IBM Verify Core SDK for iOS
* Increment version
* Copyright and naming update
* Improved support for reading and writing data and private keys
* Shared Keychain support
* Enhanced logging support in `URLSession+Extension`

### IBM Verify Authentication SDK for iOS
* Increment version
* Copyright and naming update
* `oidc` removed as default scope

### IBM Verify Adaptive SDK for iOS
* Increment version
* Copyright and naming update

### IBM Verify FIDO2™ SDK for iOS
* Increment version
* Copyright and naming update
* Custom Credential Provider support

### IBM Verify MFA SDK for iOS
* Increment version
* Copyright and naming update
* Naming consistency
* Improved signature enrollment and transaction signing
* Separated one-time (OTP) from multi-factor (MFA) authenticators
* Transaction includes `expiryTime` and `coorelationCode`
* Support for `Sendable` in factors and authenticators
* Added `createdDate` for authenticators

# v3.0.11
21 December 2024
### IBM Verify DC SDK for iOS
* Adds support for digital credentials.

### IBM Verify Core SDK for iOS
* Support for decoding a JSON array of type `T` of unknown coding key.

# v3.0.10
15 June 2024
### IBM Verify MFA SDK for iOS
* Adds `CloudRegistrationProvider.inAppInitiate` supporting in-app MFA registration.

# v3.0.9
20 February 2024
### IBM Verify MFA SDK for iOS
* Fix `FactorType` enum accessibility.
* Support for low entropy OTP generation.

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>

# v3.0.8
13 January 2024
### IBM Verify MFA SDK for iOS
* Increment version
* Fix JSON format when enrolling factor.
* Fix URL to include SCIM namespace.
* Add support for `URLSessionDelegate`.
* Update unit test JSON data files.

### IBM Verify Core SDK for iOS
* Increment version
* Make `SecKey` accessible as `keyRepresentation`
* Support for `jwkRepresentation`.

### IBM Verify Authentication SDK for iOS
* Increment version
* Make `additionalHeaders` accessible
* Support for Demonstrating Proof of Possession (DPoP) generation.
* Fix Proof Key for Code Exchange (PKCE) encoding.

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
* Add transport support for Webauthn specification 3
* Fix typo
* Enhance the sample app
<br/>
<br/>

# v3.0.7
20 July 2023
### IBM Verify MFA SDK for iOS
* Increment version
* Fix JSON format when enrolling factor.
* Fix URL to include SCIM namespace.
* Add support for `URLSessionDelegate`.

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version
* Add support for `URLSessionDelegate`.

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>

# v3.0.6
5 July 2023
### IBM Verify MFA SDK for iOS
* Increment version
* Remove OTP from being automatically registered during MFA enrolment.

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
* Fix handling of `/attestation/options` in example app
* Increment deployment info to iOS 15 in sample app
* Update labels in sample app
<br/>
<br/>

# v3.0.5
28 March 2023
### IBM Verify MFA SDK for iOS
* Increment version

### IBM Verify Core SDK for iOS
* Increment version

### IBM Verify Authentication SDK for iOS
* Increment version

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
* Fix handling of `/attestation/options` in example app
* Increment deployment info to iOS 15 in sample app
* Update labels in sample app
<br/>
<br/>

# v3.0.4
1 October 2022
### IBM Verify MFA SDK for iOS
* Added to repository

### IBM Verify Core SDK for iOS
* Increment version
* Updated `URLSession` extension
* Add support for RSA key generation, export and signing

### IBM Verify Authentication SDK for iOS
* Increment version
* Updated

### IBM Verify Adaptive SDK for iOS
* Increment version
* Increment deployment info to iOS 14.6

### IBM Verify FIDO2™ SDK for iOS
* Increment version
* Support for SwiftUI
* Increment deployment info to iOS 14.6
<br/>
<br/>

# v3.0.3
1 February 2022
### IBM Verify Authentication SDK for iOS
* Added to repository

### IBM Verify Core SDK for iOS
* Increment version
* Increment deployment info to iOS 14.6
* Added @propertyWrapper for decoding default JSON values
* Added Data extension
* Added String extension
* Added NSNumber extension
* Added KeyedDecodingContainer extension
* Added JSON codable helpers
* Updated URLSession extension

### IBM Verify Adaptive SDK for iOS
* Increment version
* Increment deployment info to iOS 14.6

### IBM Verify FIDO2™ SDK for iOS
* Increment version
* Increment deployment info to iOS 14.6
<br/>
<br/>

# v3.0.2
1 December 2021
### IBM Verify Core SDK for iOS
* Added to repository

### IBM Verify Adaptive SDK for iOS
* Increment version

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>

# v3.0.1
17 November 2021
### IBM Verify Adaptive SDK for iOS
* Added to repository

### IBM Verify FIDO2™ SDK for iOS
* Increment version
<br/>
<br/>

# v3.0.0
6 October 2021
### IBM Verify FIDO2™ SDK for iOS
* Added to repository
