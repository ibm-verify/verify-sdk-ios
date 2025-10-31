# IBM Verify Digital Credentials Sample App for iOS

The digital credentials sample app is an end-to-end mobile app that uses features in [IBM Verify Access](https://www.ibm.com/au-en/products/verify-access) (on-premises) and [IBM Verify](https://www.ibm.com/verify/verify-identity) (cloud).

## Getting started

IBM Verify Identity Access enables businesses, governments, and individuals to issue, manage, and verify digital credentials with the Digital Credentials feature.
[IBM Verify Identity Access Digital Credentials configuration](https://www.ibm.com/docs/en/sva/11.0.0?topic=configuring-verify-identity-access-digital-credentials-configuration)

## Before running the app

Your IBM Verify Identity Access (ISVA) administrator will provide you with username and password and the endpoint to start the wallet provisioning process.

## Running the app
### Update the project settings
1. After opening the project in Xcode, change the **Team** selection under **Signing & Capabilities** in the **Target** list
2. Connect your iOS mobile device or use the Xcode simulator

### Creating a wallet
1. Press ⌘R to run the project
2. Tap **Create Wallet** (you'll be prompted to allow the app to access the camera on the device)
3. Scan the code that appears in the browser from the pervious section
4. Enter an account name, a username and password, then tap **Continue**
5. Tap **Done**. Details about the wallet are displayed.

### Accepting a credential
1. Tap the **Credentials** tab.
2. Tap the **Create Wallet** to launch the camera to scan the QR code
3. The credential issuer details are displayed, tap **Continue**. 
4. Details about the credentual are displayed, tap **Add to wallet**
5. Tap **Done**. The list of existing credential are displayed.

### Verifying a credential
1. Tap the **Verifications** tab.
2. Tap the **Verify Credential** to launch the camera to scan the QR code
3. The verifier details are displayed, tap **Continue**. 
4. Details about the verification request are displayed, tap **Preview Identity Details**
5. A list of identity attribute claims about the credential are displayed. This is what is provided to the verifier., tap **Allow Verification**
5. Tap **Done**. The list of existing verification are displayed.  Tap **Refresh** to retrieve all past verifications.

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
