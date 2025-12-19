//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//


import XCTest
import Authentication
import Core
import CryptoKit
@testable import MFA
import LocalAuthentication

class OnPremiseRegistrationProviderTest: XCTestCase {
    let urlBase = "https://mmfa.securitypoc.com"
    let scanResult = """
    {
        "code": "A1B2C3D4",
        "options":"ignoreSslCerts=false",
        "details_url": "https://mmfa.securitypoc.com/mga/sps/mmfa/user/mgmt/details",
        "version": 1,
        "client_id": "IBMVerify"
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
    
    /// Test the scan initiation of an on-premise provider .
    func testScanInitializeAuthenticator() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
    }
    
    /// Test the initiation of an on-premise provider and enrolls a TOTP factor.
    func testInitializeAuthenticatorWithAccount() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")

        let otpUrl = URL(string: "\(urlBase)/mga/sps/mga/user/mgmt/otp/totp")!
        MockURLProtocol.urls[otpUrl] = MockHTTPResponse(response: HTTPURLResponse(url: otpUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentTOTP")

        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account")
        XCTAssertNotNil(provider)
    }
    
    /// Test the initiation of an on-premise provider and fails the TOTP enrollment.
    func testInitializeAuthenticatorFailTOTPEnrollment() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")

        let otpUrl = URL(string: "\(urlBase)/mga/sps/mga/user/mgmt/otp/totp")!
        MockURLProtocol.urls[otpUrl] = MockHTTPResponse(response: HTTPURLResponse(url: otpUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.failedEnrollmentTOTP")

        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        do {
            let _ = try await controller.initiate(with: "OnPremise account")
        }
        catch let error {
            XCTAssertTrue(error is OnPremiseRegistrationError)
        }
    }
    
    /// Test the scan and create an insance of the on-premise registration provider, then get the next enrollment.
    func testNextEnrollment() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")

        let otpUrl = URL(string: "\(urlBase)/mga/sps/mga/user/mgmt/otp/totp")!
        MockURLProtocol.urls[otpUrl] = MockHTTPResponse(response: HTTPURLResponse(url: otpUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentTOTP")
      
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "Onpremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider.enrollUserPresence()
        }
        catch {
            XCTFail("Expected call to not throw, but it did: \(error)")
        }
    }
    
    /// Test the scan and create an insance of the on-premise registration provider, then detemine which signatures are enabled for enrollment.
    func testAvailableEnrolments() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")

        let otpUrl = URL(string: "\(urlBase)/mga/sps/mga/user/mgmt/otp/totp")!
        MockURLProtocol.urls[otpUrl] = MockHTTPResponse(response: HTTPURLResponse(url: otpUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentTOTP")
      
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        XCTAssertEqual(provider.canEnrollBiometric, true)
        
        // Then
        XCTAssertEqual(provider.canEnrollUserPresence, true)
    }
    
    /// Test the scan and create an insance of the on-premise registration provider, then get the next enrollments until an error is thrown
    func testNextEnrollmentThrowNoEnrollments() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiateNoEnrollments")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        do {
            let _ = try await controller.initiate(with: "John Doe", pushToken: "abc123")
        }
        catch let error {
            XCTAssertTrue(error is OnPremiseRegistrationError)
        }
    }
    
    /// Test the initiation where enrollment face and fingerprint are available.  This test will remove the fingerprint factor.
    /// - note: This test uses `LaContext` to determine the biometric sensor.
    func testNextEnrollmentIsBiometricFactor() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        let otpUrl = URL(string: "\(urlBase)/mga/sps/mga/user/mgmt/otp/totp")!
        MockURLProtocol.urls[otpUrl] = MockHTTPResponse(response: HTTPURLResponse(url: otpUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentTOTP")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider.enrollBiometric(savePrivateKey: MFARegistrationControllerTests.saveBiometricPrivateKey, context: BiometricContext(), reason: "ID Required")
        }
        catch {
            XCTFail("Expected call to not throw, but it did: \(error)")
        }
    }
    
    /// Test the initiation, get the next enrollment, then enroll the user presence factor.
    func testEnrollUserPresenceSuccess() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiateUserPresence")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        let enrollmentUrl = URL(string: "\(urlBase)/scim/Me")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentUserPresence")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider.enrollUserPresence(savePrivateKey: MFARegistrationControllerTests.saveUserPresencePrivateKey)
        }
        catch {
            XCTFail("Expected call to not throw, but it did: \(error)")
        }
    }
    
    /// Test the initiation, get the next enrollment, then enroll the biometric factor.
    func testEnrollBiometricSuccess() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiateFingerprint")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        let enrollmentUrl = URL(string: "\(urlBase)/scim/Me")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentFingerprint")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider.enrollBiometric(savePrivateKey: MFARegistrationControllerTests.saveBiometricPrivateKey, context: BiometricContext(), reason: "ID youself")
        }
        catch {
            XCTFail("Expected call to not throw, but it did: \(error)")
        }
    }
    
    /// Test the scan and create an insance of the on-premise registration provider, then get the next enrollment with an error.
    func testEnrollmentError() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiateUserPresence")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        let enrollmentUrl = URL(string: "\(urlBase)/scim/Me")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 404, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentError")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider.enrollBiometric(savePrivateKey: MFARegistrationControllerTests.saveBiometricPrivateKey, context: BiometricContext(), reason: "ID youself")
        }
        catch let error {
            XCTAssertTrue(error is OnPremiseRegistrationError)
        }
    }
    
    /// Test the initiation, get the next enrollment, then enroll the fingerprint factor, failing with an unknow signature method.
    func testEnrollmentFailed() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiateFingerprint")
        
        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        let enrollmentUrl = URL(string: "\(urlBase)/scim/Me")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentFailed")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        do {
            try await provider.enrollBiometric(savePrivateKey: MFARegistrationControllerTests.saveBiometricPrivateKey, context: BiometricContext(), reason: "ID youself")
        }
        catch let error {
            XCTAssertTrue(error is OnPremiseRegistrationError)
        }
    }
    
    /// Test the finalization of the a registration with TOTP.
    func testFinalizeRegistration() async throws -> any MFAAuthenticatorDescriptor {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")

        let otpUrl = URL(string: "\(urlBase)/mga/sps/mga/user/mgmt/otp/totp")!
        MockURLProtocol.urls[otpUrl] = MockHTTPResponse(response: HTTPURLResponse(url: otpUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentTOTP")

        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        let authenticator = try await provider.finalize()
        XCTAssertNotNil(authenticator)
        XCTAssertEqual(authenticator.token.accessToken, "A1b2C3D4")
        XCTAssertNil(authenticator.userPresence)
        XCTAssertNil(authenticator.biometric)
        
        // Then
        return authenticator
    }
    
    /// Test the scan and create an insance of the on-premise registration provider, then enrol with the SDK creating the keys
    func testFinalizeRegistrationWithKeys() async throws -> any MFAAuthenticatorDescriptor {
        // Given
        let registrationUrl = URL(string: "\(urlBase)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiateUserPresence")

        let tokenUrl = URL(string: "\(urlBase)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")
        
        let enrollmentUrl = URL(string: "\(urlBase)/scim/Me")!
        MockURLProtocol.urls[enrollmentUrl] = MockHTTPResponse(response: HTTPURLResponse(url: enrollmentUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentUserPresence")
        
        // Where
        let controller = MFARegistrationController(json: scanResult)
         
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "OnPremise account", pushToken: "abc123")
        XCTAssertNotNil(provider)
        
        // Then
        try await provider.enrollUserPresence()
        
        // Then
        let authenticator = try await provider.finalize()
        XCTAssertNotNil(authenticator)
        
        return authenticator
    }
}
