# IBM Verify MFA Sample App for iOS

The MFA sample app is an end-to-end mobile app that uses features in [IBM Verify Access](https://www.ibm.com/au-en/products/verify-access) (on-premises) and [IBM Verify](https://www.ibm.com/verify/verify-identity) (cloud).

## Getting started

  The resource links in the prerequisites explain and demonstrate how you create a new tenant application and configure the security settings to enable multi-factor authentication to use in the sample app.

### Prerequisites

- Getting started

> See [Before you begin](https://docs.verify.ibm.com/verify/docs/guides)

- Multi-factor authentication

> See [Multi-factor authentication](https://docs.verify.ibm.com/verify/docs/multi-factor-authentication)

- Registering the app

> See [Inline MFA enrollment](https://docs.verify.ibm.com/verify/docs/inline-mfa-enrollment)

## Before running the app

1. Sign into your tenant
2. Click your initials in the top-right corner of the My Apps landing page
3. Click **Profile & Settings**
4. Click **Security** tab
5. Click **Add new method +**
6. Click **Add device** next to "IBM Verify App"
7. Follow the prompts to when a QR code appears

## Running the app
### Update the project settings
1. After opening the project in Xcode, change the **Team** selection under **Signing & Capabilities** in the **Target** list
2. Connect your iOS mobile device or use the Xcode simulator

### Register and enroll the app
1. Press ⌘R to run the project
2. Tap **Get Started** (you'll be prompted to allow the app to access the camera on the device)
3. Scan the code that appears in the browser from the pervious section
4. Enter an account nickname, then tap **Continue**
5. Depending on your tenants' configuration of "Authentication factors", you'll be prompted to allow the app to access Touch ID or Face ID on the device

### Testing MFA
1. Switch to the browser where you scanned the QR code - your device should now be registered
2. Expand the device under "IBM Verify"
3. Click the ⋮ symbol to the right of a "Method" i.e "Touch approval"
4. Select **Test Method**
5. Switch to the MFA app and tap **Check Transaction**
6. The transaction sheet will appear, tap **Approve** or **Deny** 
7. The status of the transaction will appear in the browser.

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
