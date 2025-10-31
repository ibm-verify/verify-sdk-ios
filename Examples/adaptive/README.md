# IBM Verify Adaptive Sample App for iOS

The Adaptive Sample App is an end-to-end mobile app that uses IBM Verify to perform risk and policy evaluation.

## Getting started

The resource links in the prerequisites explain and demonstrate how you create a new tenant application configured with Adaptive Access capabilities.

### Prerequisites

- Install and configure the demo
[Proxy SDK](https://github.com/IBM-Verify/adaptive-proxy-sdk-javascript) on a Node server by running `npm install adaptive-proxy-sdk`
> NOTE: Also run `npm install` in the demo folder.

- Generate and download the Trusteer SDK via IBM Verify admin portal for the application.

> See [On-board a native application](https://docs.verify.ibm.com/verify/docs/adaptive-access-sdk-adaptive-sdk-for-ios)

## Configure the app

1. After opening the project in Xcode, change the **Team** selection under **Signing & Capabilities** in the **Target** list
2. Navigate to the **Build Phases** tab, expand the “Link Binary With Libraries” list and  click on the + button. Add `tazSDK.xcframework` from the location where the downloaded Trusteer SDK resides.
3. In Finder, create a new folder named **tas**.  Copy `default_conf.rpkg` and `manifest.rpkg` from the Trusteer SDK download location into the **tas** folder.
4. Drag the **tas** folder into the project. When prompted, ensure the checkbox "Copy items if needed" is checked
5. Drag `TrusteerCollectionService.swift` into the project from the location the Trusteer SDK was downloaded.  When prompted, ensure the checkbox "Copy items if needed" is checked
6. Open `AppHelper.swift` and change the `baseUrl` variable to be the IP address and port of the Proxy SDK you configured as part of the prerequisites. i.e `192.168.1.10:3000`
7. Open `MainViewController.swift` and find the **`TODO`** and comment out `AdaptiveContext.shared.collectionService = TrusteerCollectionService()`. 

## Running the app

1. Press ⌘R to run the project
2. Tap **Perform Assessment**
3. Tap **Password**
4. Enter the **Username** and **Password** for a tenant user
5. Tap **Evaluate**

> Note: depending on how you have configured application policy on your tenant, you may be prompted for additional evaluation.

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
