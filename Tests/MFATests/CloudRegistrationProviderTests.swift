//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
import Authentication
import Core
import CryptoKit
@testable import MFA
import LocalAuthentication
import Darwin // Essential for C compatibility functions



class BiometricContext: LAContext {
    func canEvaluatePolicy(_ policy: LAPolicy, error: inout NSError?) -> Bool {
        true
    }
    
    override func evaluatePolicy(_ policy: LAPolicy, localizedReason: String) async throws -> Bool {
        true
    }
}

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
    
    func testEnrollFailsWhenInitializationInfoIsMissing() async {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=true")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", pushToken: "abc123") as? CloudRegistrationProvider
        XCTAssertNotNil(provider)
        
        // Then
        provider?.initializationInfo = nil
        
        do {
            try await provider?.enrollUserPresence(savePrivateKey: MFARegistrationControllerTests.saveUserPresencePrivateKey)
        }
        catch let error as MFARegistrationError {
            switch error {
            case .invalidState:
                XCTAssertNotNil(error)
            default:
                XCTFail("Unexpected error type: \(error)")
            }
        }
        catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }
    
    /// Test the initiation of a cloud provider by handling the enrollment event.
    func testInitializeAuthenticatorWithAccount() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
    }
    
    /// Test the initiation of a cloud provider with no enroll signatures.
    func testInitializeAuthenticatorNoSignatures() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
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
        XCTAssertNil(authenticator.userPresence)
        XCTAssertNil(authenticator.biometric)
    }
    
    /// Test the scan and create an insance of the cloud registration provider, then attempt to enrol user presence which is not enabled..
    func testUserPresenceNotEnabled() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        do {
            try await provider.enrollUserPresence()
        }
        catch let error as MFARegistrationError {
            if case .signatureMethodNotEnabled(type: "User Presence") = error {
                XCTAssertNotNil(error)
            }
            else {
                XCTFail("Unexpected error type: \(error)")
            }
        }
    }
    
    /// Test the scan and create an insance of the on-premise registration provider, then detemine which signatures are enabled for enrollment.
    func testAvailableEnrolments() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        XCTAssertEqual(provider.canEnrollBiometric, true)
        
        // Then
        XCTAssertEqual(provider.canEnrollUserPresence, false)
    }
    
    /// Test the scan and create an insance of the cloud registration provider, then enroll user presence.
    func testNextEnrollmentUserPrecenceEnrollments() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateTOTP")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try? await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider?.enrollUserPresence(savePrivateKey: MFARegistrationControllerTests.saveUserPresencePrivateKey)
        }
        catch let error as MFARegistrationError {
            if case .signatureMethodNotEnabled(type: "User Presence") = error {
                XCTAssertNotNil(error)
            }
            else {
                XCTFail("Unexpected error type: \(error)")
            }
        }
    }
    
    /// Test the initiation where enrollment face and fingerprint are available.  This test will remove the fingerprint factor.
    /// - note: This test uses `LaContext` to determine the biometric sensor.
    func testNextEnrollmentBiometricFactor() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateBiometry")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try? await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider?.enrollUserPresence(savePrivateKey: MFARegistrationControllerTests.saveUserPresencePrivateKey)
        }
        catch {
            XCTAssert(error is MFARegistrationError)
        }
    }
    
    /// Test the initiation, get the next enrollment, then enroll the face factor.
    func testEnrollFaceSuccess() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateFace")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentFace")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try? await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider?.enrollBiometric(savePrivateKey: MFARegistrationControllerTests.saveBiometricPrivateKey, context: BiometricContext(), reason: "ID required")
        }
        catch {
            XCTAssert(error is MFARegistrationError)
        }
    }
    
    /// Test the initiation, get the next enrollment, then enroll the fingerprint factor.
    func testEnrollFingerprintSuccess() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateFingerprint")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentFingerprint")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try? await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider?.enrollBiometric(savePrivateKey: MFARegistrationControllerTests.saveBiometricPrivateKey, context: BiometricContext(), reason: "ID required")
        }
        catch {
            XCTAssert(error is MFARegistrationError)
        }
    }
    
    /// Test the initiation, get the next enrollment, then enroll the user presence factor.
    func testEnrollUserPresenceSuccess() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiateUserPresence")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 201, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentUserPresence")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try? await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider?.enrollUserPresence(savePrivateKey: MFARegistrationControllerTests.saveUserPresencePrivateKey)
        }
        catch {
            XCTAssert(error is MFARegistrationError)
        }
    }
    
    /// Test the scan and create an insance of the cloud registration provider, then get the next enrollment with an error.
    func testEnrollmentError() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        let enrollmentUrl = URL(string: "\(urlBase)/v1.0/authnmethods/signatures")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 400, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.enrollmentError")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider.enrollBiometric(savePrivateKey: MFARegistrationControllerTests.saveBiometricPrivateKey, context: BiometricContext(), reason: "ID Required")
        }
        catch let error {
            XCTAssertTrue(error is URLSessionError)
        }
    }
    
    /// Test the finalization of the a registration with user presence.
    func testFinalizeRegistration() async throws -> any MFAAuthenticatorDescriptor {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
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
        let provider = try await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        try await provider.enrollUserPresence()
        
        // Then
        let authenticator = try await provider.finalize()
        XCTAssertNotNil(authenticator)
        XCTAssertEqual(authenticator.token.accessToken, "a1b2c3")
        XCTAssertNotNil(authenticator.userPresence)
        
        // Then
        return authenticator
    }
    
        
    /// Test the finalization of the a registration with face and generate keys.
    func testFinalizeRegistrationWithKeys() async throws  {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
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
        let provider = try? await controller.initiate(with: "Cloud account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        try await provider?.enrollBiometric(savePrivateKey: MFARegistrationControllerTests.saveBiometricPrivateKey, context: BiometricContext(), reason: "ID Required")
        
        // Then
        let authenticator = try? await provider?.finalize()
        XCTAssertNotNil(authenticator)
        XCTAssertEqual(authenticator?.token.accessToken, "a1b2c3")
        XCTAssertNil(authenticator?.userPresence)
        XCTAssertNotNil(authenticator?.biometric)
    }
    
    /// Test the finalization of the a registration
    func testFinalizeRegistrationUnderlyingError() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?skipTotpEnrollment=true")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 404, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try! await controller.initiate(with: "Cloud account", pushToken: "abc123")
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
