//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//


import XCTest
@testable import MFA

class MFAAttributeInfoTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    /// Test the initialization of MFAAttributeInfo.
    func testInit() throws {
        // Given, When, Then
        XCTAssertNotNil(MFAAttributeInfo.operatingSystemVersion)
        XCTAssertNotNil(MFAAttributeInfo.operatingSystem)
        XCTAssertNotNil(MFAAttributeInfo.applicationName)
        XCTAssertNotNil(MFAAttributeInfo.applicationVersion)
        XCTAssertNotNil(MFAAttributeInfo.applicationBundleIdentifier)
        XCTAssertTrue(MFAAttributeInfo.hasFrontCamera)
        XCTAssertNotNil(MFAAttributeInfo.hasFaceID)
        XCTAssertNotNil(MFAAttributeInfo.hasTouchID)
        XCTAssertFalse(MFAAttributeInfo.deviceInsecure)
        XCTAssertNotNil(MFAAttributeInfo.model)
        XCTAssertNotNil(MFAAttributeInfo.name)
        XCTAssertNotNil(MFAAttributeInfo.deviceID)
        XCTAssertNotNil(MFAAttributeInfo.frameworkVersion)
    }
    
    /// Test the conversion of the attributes to a dictionary.
    func testConvert() throws {
        // Given, When
        let values = MFAAttributeInfo.dictionary()
        
        // Then
        XCTAssertNotNil(values["osVersion"])
        XCTAssertNotNil(values["platformType"])
        XCTAssertNotNil(values["applicationVersion"])
        XCTAssertNotNil(values["applicationId"])
        XCTAssertNotNil(values["frontCameraSupport"])
        XCTAssertNotNil(values["faceSupport"])
        XCTAssertNotNil(values["fingerprintSupport"])
        XCTAssertNotNil(values["deviceInsecure"])
        XCTAssertNotNil(values["deviceType"])
        XCTAssertNotNil(values["deviceName"])
        XCTAssertNotNil(values["deviceId"])
        XCTAssertNotNil(values["verifySdkVersion"])
    }
    
    /// Test the conversion of the attributes to a dictionary. where the keys are in snake csse.
    func testConvertAsSnakeCase() throws {
        // Given, When
        let values = MFAAttributeInfo.dictionary(snakeCaseKey: true)
        
        // Then
        XCTAssertNotNil(values["os_version"])
        XCTAssertNotNil(values["platform_type"])
        XCTAssertNotNil(values["application_version"])
        XCTAssertNotNil(values["application_id"])
        XCTAssertNotNil(values["front_camera_support"])
        XCTAssertNotNil(values["face_support"])
        XCTAssertNotNil(values["fingerprint_support"])
        XCTAssertNotNil(values["device_insecure"])
        XCTAssertNotNil(values["device_type"])
        XCTAssertNotNil(values["device_name"])
        XCTAssertNotNil(values["device_id"])
        XCTAssertNotNil(values["verify_sdk_version"])
    }
}

