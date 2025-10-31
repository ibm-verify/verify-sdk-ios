# IBM Verify FIDO2™ Sample App for iOS

The FIDO2 sample app is an end-to-end mobile app which uses the FIDO2 server features in IBM Verify Access (on-premises) and IBM Verify (cloud).

## Getting started

  The resource links in the prerequisites explain and demonstrate how you create a new tenant application with OAuth and walk through setting up a FIDO2 relying party.

### Prerequisites

- OAuth2 using resource owner password credential (ROPC)

> See [Create an application using ROPC](https://docs.verify.ibm.com/verify/docs/developer-portal-ropc-example)

- FIDO relying party

> See [Create a FIDO Relying Party for WebAuthn](https://docs.verify.ibm.com/verify/docs/support-developers-create-a-fido-relying-party)

- Authenticator metadata (optional)

> See [FIDO2 metadata](https://docs.verify.ibm.com/verify/docs/user-authentication-fido2#metadata)


## Running the app

1. After opening the project in Xcode, change the **Team** selection under **Signing & Capabilities** in the **Target** list
2. Connect your iOS mobile device
3. Press ⌘R to run the project
4. Tap **Get Started** under IBM Verify
5. Enter your **Tenant URL**  i.e `https://sdk.verify.ibm.com`
6. Enter the **Client ID** obtained from the tenant application configuration under the **Sign-on** tab
7. Enter the **Username** and **Password** for a tenant user
8. Tap **Login**
9. On the **Attestation Options** screen, tap **Initiate Registration**
10. On the **Authenticator Options** screen, enter an optional **Nickname**, then tap **Register**

> Note: the Secure Enclave is used for generating the private key and therefore can only run on a physical device. 

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
<br/><br/>
FIDO™ and FIDO2™  are  trademarks (registered in numerous countries) of FIDO Alliance, Inc.
