//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
import Authentication
import Core
import CryptoKit
@testable import MFA

// MARK: - Mock

class CloudRegistrationProviderTests: XCTestCase {
    let urlBase = "https://sdk.verify.ibm.com"
    let scanResult = """
        {
            "code": "abc123",
            "accountName": "Savings Account",
            "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
            "version": {
                "number": "1.0.0",
                "platform": "com.ibm.security.access.verify"
            }
        }
    """
    
    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(MockURLProtocol.self)
    }

    override func tearDown() {
        super.tearDown()
        URLProtocol.unregisterClass(MockURLProtocol.self)
    }
    
    /// Test the initiation of a cloud provider.
    func testInAppInitializeAuthenticator() async throws {
        // Given
        let initiateUrl = URL(string: "\(urlBase)/v1.0/authenticators/initiation")!
        MockURLProtocol.urls[initiateUrl] = MockHTTPResponse(response: HTTPURLResponse(url: initiateUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.qrscan")
        
        do {
            // Where
            let json = try await CloudRegistrationProvider.inAppInitiate(with: initiateUrl, accessToken: "09876zxyt", clientId: "a8f0043d-acf5-4150-8622-bde8690dce7d", accountName: "Test")
             
            // Then
            XCTAssertNotNil(json)
            
            let provider = try CloudRegistrationProvider(json: json)
            XCTAssertNotNil(provider)
        }
        catch let error {
            XCTAssertTrue(error is URLSessionError)
        }
    }
    
    /// Test the scan initiation of a cloud provider.
    func testScanInitializeAuthenticator() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
    }
    
    /// Test the initiation of a cloud provider by handling the enrollment event.
    func testInitializeAuthenticatorWithAccount() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
    }
    
    /// Test the initiation of a cloud provider with a TOTP factor.
    func testInitializeAuthenticatorWithTOTP() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
      
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let authenticator = try await provider.finalize()
        XCTAssertNotNil(authenticator)
        XCTAssertTrue(authenticator.allowedFactors.contains(where: { $0.valueType is TOTPFactorInfo }))
    }
    
    /// Test the scan and create an insance of the on-premise registration provider, then ffinalizes the authenticator with no factors.
    func testEnrolmentsSkipTOTP() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateNoTOTP")
        
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
      
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let authenticator = try await provider.finalize()
        XCTAssertNotNil(authenticator)
        
        // Then
        XCTAssertFalse(authenticator.allowedFactors.contains(where: { $0.valueType is TOTPFactorInfo }))
    }
    
    /// Test the scan and create an insance of the cloud registration provider, then get the next enrollment.
    func testNextEnrollment() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        if let factor = await provider.nextEnrollment() {
            XCTAssertNotNil(factor)
        }
    }
    
    /// Test the scan and create an insance of the cloud registration provider, then get the count of available signature enrollments.
    func testCountOfAvailableEnrolments() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        XCTAssertEqual(provider.countOfAvailableEnrollments, 1)
    }
    
    /// Test the scan and create an insance of the cloud registration provider, then get the next enrollments until nil.
    func testNextEnrollmentThrowNoEnrollments() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        while let factor = await provider.nextEnrollment() {
            XCTAssertNotNil(factor)
        }
    }
    
    /// Test the initiation where enrollment face and fingerprint are available.  This test will remove the fingerprint factor.
    /// - note: This test uses `LaContext` to determine the biometric sensor.
    func testNextEnrollmentBiometricFactor() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateBiometry")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let factor = await provider.nextEnrollment()
        XCTAssertNotNil(factor)
        XCTAssertTrue(factor!.biometricAuthentication)
    }
    
    /// Test the initiation, get the next enrollment, then enroll the face factor.
    func testEnrollFaceSuccess() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateFace")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentFace")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let factor = await provider.nextEnrollment()
        XCTAssertNotNil(factor)
        XCTAssertTrue(factor!.biometricAuthentication)
        
        // Then
        try await provider.enroll(with: "biometric", publicKey: "MIICzDCCAbQCCQDH8Gv", signedData: "f536975d06c")
    }
    
    /// Test the initiation, get the next enrollment, then enroll the fingerprint factor.
    func testEnrollFingerprintSuccess() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateFingerprint")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentFingerprint")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let factor = await provider.nextEnrollment()
        XCTAssertNotNil(factor)
        XCTAssertTrue(factor!.biometricAuthentication)
        
        // Then
        try await provider.enroll(with: "biometric", publicKey: "MIICzDCCAbQCCQDH8Gv", signedData: "f536975d06c")
    }
    
    /// Test the initiation, get the next enrollment, then enroll the user presence factor.
    func testEnrollUserPresenceSuccess() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateUserPresence")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentUserPresence")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let factor = await provider.nextEnrollment()
        XCTAssertNotNil(factor)
        XCTAssertFalse(factor!.biometricAuthentication)
    
        // Then
        try await provider.enroll(with: "user presence", publicKey: "MIICzDCCAbQCCQDH8Gv", signedData: "f536975d06c")
    }
    
    /// Test the scan and create an insance of the cloud registration provider, then get the next enrollment with an error.
    func testEnrollmentError() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 400, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentError")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            let factor = await provider.nextEnrollment()
            XCTAssertNotNil(factor)
                
            try await provider.enroll(with: "biometric", publicKey: "MIICzDCCAbQCCQDH8Gv", signedData: "f536975d06c")
        }
        catch let error {
            XCTAssertTrue(error is URLSessionError)
        }
    }
    
    /// Test the finalization of the a registration with user presence.
    func testFinalizeRegistration() async throws -> any MFAAuthenticatorDescriptor {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentUserPresence")
      
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let factor = await provider.nextEnrollment()
        XCTAssertNotNil(factor)
        
        // Then
        try await provider.enroll(with: "Factor", publicKey: "abc123", signedData: "abc123")
        
        // Then
        let authenticator = try await provider.finalize()
        XCTAssertNotNil(authenticator)
        XCTAssertEqual(authenticator.token.accessToken, "a1b2c3")
        XCTAssertTrue(authenticator.allowedFactors.count == 1)
        XCTAssertTrue(authenticator.allowedFactors.contains(where: { $0.valueType is UserPresenceFactorInfo }))
        
        // Then
        return authenticator
    }
    
    /// Test the finalization of the a registration with face.
    func testFinalizeRegistrationWithFace() async throws  {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateFace")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentFace")
      
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let factor = await provider.nextEnrollment()
        XCTAssertNotNil(factor)
        
        // Then
        try await provider.enroll(with: "Factor", publicKey: "abc123", signedData: "abc123")
        
        // Then
        let authenticator = try await provider.finalize()
        XCTAssertNotNil(authenticator)
        XCTAssertEqual(authenticator.token.accessToken, "a1b2c3")
        XCTAssertTrue(authenticator.allowedFactors.count == 1)
        XCTAssertTrue(authenticator.allowedFactors.contains(where: { $0.valueType is FaceFactorInfo }))
    }
    
    /// Test the finalization of the a registration with face and generate keys.
    func testFinalizeRegistrationWithKeys() async throws  {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateFace")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentFace")
      
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let factor = await provider.nextEnrollment()
        XCTAssertNotNil(factor)
        
        // Then
        try await provider.enroll()
        
        // Then
        let authenticator = try await provider.finalize()
        XCTAssertNotNil(authenticator)
        XCTAssertEqual(authenticator.token.accessToken, "a1b2c3")
        XCTAssertTrue(authenticator.allowedFactors.count == 1)
        XCTAssertTrue(authenticator.allowedFactors.contains(where: { $0.valueType is FaceFactorInfo }))
    }
    
    /// Test the finalization of the a registration
    func testFinalizeRegistrationUnderlyingError() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 404, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            let _ = try await provider.finalize()
        }
        catch let error {
            XCTAssertTrue(error is URLSessionError)

            // Verify that our error is equal to what we expect
            XCTAssertEqual(error as? URLSessionError, .invalidResponse(statusCode: 404, description: ""))
        }
    }
}
