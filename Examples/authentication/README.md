# IBM Verify Authentication Sample App for iOS

The Authentication sample app is an end-to-end mobile app which uses an OAuth and OIDC features in [IBM Verify Access](https://www.ibm.com/au-en/products/verify-access) (on-premises) and [IBM Verify](https://www.ibm.com/verify/verify-identity) (cloud).

## Getting started

  The resource links in the prerequisites explain and demonstrate how you create a new tenant application with OAuth and walk through setting up the authenitcation sample application.

### Prerequisites

- OAuth2 using authorization code flow (AZN)

> See [Create an application using AZN](https://docs.verify.ibm.com/verify/docs/authorization-code-example)

- Ensure that the redirect URL is `verifysdk://auth/callback`


## Running the app

1. After opening the project in Xcode, change the **Team** selection under **Signing & Capabilities** in the **Target** list
2. Connect your iOS mobile device or use the Xcode simulator
3. Press ⌘R to run the project
4. Enter your tenant **Authorize Endpoint** i.e `https://sdk.verify.ibm.com/v1.0/endpoint/default/authorize`
5. Enter your tenant **Token Endpoint**  i.e `https://sdk.verify.ibm.com/v1.0/endpoint/default/token`
6. Enter the **Redirect Callback**  i.e `verifysdk://auth/callback`
7. Enter the **Client ID** obtained from the tenant application configuration 
8. Tap **Use PKCE** if you configured the tenant application to use Proof Key for Code Exchange verification
9. Tap **Share session** if the sample authentication application will persist the session across authentication attemps
10. Tap **Include state** to send a random string in the request.  The authorization server will return this value when the authorization code is generated.
11. Tap **Get Started**


> NOTE: If you configured your tenant application to use a client secret, add this value to the `clientSecret` variable in **SigninViewModel.swift**.

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
