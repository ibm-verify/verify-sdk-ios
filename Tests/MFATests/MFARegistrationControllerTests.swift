//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
@testable import MFA

class MFARegistrationControllerTests: XCTestCase {
    let urlBaseCloud = "https://sdk.verify.ibm.com"
    let urlBaseOnPremise = "https://mmfa.securitypoc.com"
    let scanResultCloud = """
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
    
    let scanResultOnPremise = """
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

    /// Test the scan and create an instance of the cloud registration provider.
    func testInitiateCloudRegistration() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBaseCloud)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        // Where
        let controller = MFARegistrationController(json: scanResultCloud)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "John Doe", skipTotpEnrollment: false, pushToken: "abc123")
        XCTAssertNotNil(provider)
        XCTAssertTrue(provider is CloudRegistrationProvider)
    }
    
    /// Test the scan and create an instance of the on-premise registration provider.
    func testInitiateOnPremiseRegistration() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBaseOnPremise)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")

        let tokenUrl = URL(string: "\(urlBaseOnPremise)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")

        let otpUrl = URL(string: "\(urlBaseOnPremise)/mga/sps/mga/user/mgmt/otp/totp")!
        MockURLProtocol.urls[otpUrl] = MockHTTPResponse(response: HTTPURLResponse(url: otpUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentTOTP")

        // Where
        let controller = MFARegistrationController(json: scanResultOnPremise)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let provider = try await controller.initiate(with: "John Doe", pushToken: "abc123")
        XCTAssertNotNil(provider)
        XCTAssertTrue(provider is OnPremiseRegistrationProvider)
    }
    
    /// Test the scan and create an instance of the on-premise registration provider with additional data.
    func testInitiateOnPremiseRegistrationWithAdditionalData() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBaseOnPremise)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")

        let tokenUrl = URL(string: "\(urlBaseOnPremise)/mga/sps/oauth/oauth20/token")!
        MockURLProtocol.urls[tokenUrl] = MockHTTPResponse(response: HTTPURLResponse(url: tokenUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.tokenRefresh")

        let otpUrl = URL(string: "\(urlBaseOnPremise)/mga/sps/mga/user/mgmt/otp/totp")!
        MockURLProtocol.urls[otpUrl] = MockHTTPResponse(response: HTTPURLResponse(url: otpUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.enrollmentTOTP")

        // Where
        let controller = MFARegistrationController(json: scanResultOnPremise)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        let additionalData: [String: Any] = ["country": "Australia", "numberOfBadges": 3, "isAllowed": true]
        let provider = try await controller.initiate(with: "John Doe", pushToken: "abc123", additionalData: additionalData)
        XCTAssertNotNil(provider)
        XCTAssertTrue(provider is OnPremiseRegistrationProvider)
    }
    
    /// Test the scan and create an instance registration controller and test the domain.
    func testInitiateCloudRegistrationDomain() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBaseCloud)/v1.0/authenticators/registration?skipTotpEnrollment=false")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        // Where
        let controller = MFARegistrationController(json: scanResultCloud)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        XCTAssertEqual(controller.domain, registrationUrl.host)
    }
        
    /// Test the scan and create an instance registration controller and test the domain.
    func testInitiateOnPremiseRegistrationDomain() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBaseOnPremise)/mga/sps/mmfa/user/mgmt/details")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "onpremise.initiate")
        
        // Where
        let controller = MFARegistrationController(json: scanResultOnPremise)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        XCTAssertEqual(controller.domain, registrationUrl.host)
    }
    
    /// Test the scan and attempt to create an instance of the unknown registration provider.
    func testInitiateFailed() async throws {
        // Given
        let registrationUrl = URL(string: "\(urlBaseCloud)/v1.0/authenticators/registration")!
        MockURLProtocol.urls[registrationUrl] = MockHTTPResponse(response: HTTPURLResponse(url: registrationUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.initiate")
        
        struct UnknownRegistrationScanInfo {
            public let code: String
            public let uri: URL

            /// The account name associated with the service.
            public var accountName: String?

            /// The root level JSON structure for decoding.
            private enum CodingKeys: String, CodingKey {
                case code
                case uri = "registrationUri"
                case accountName
            }
        }
        
        // Where
        let json = """
        {
            "code": "A1B2C3D4",
            "client_id": "IBMVerify"
        }
        """
        let controller = MFARegistrationController(json: json)
        
        // Then
        XCTAssertNotNil(controller)
        
        // Then
        do {
            let _ = try await controller.initiate(with: "John Doe", pushToken: "abc123")
        }
        catch let error {
            XCTAssertTrue(error is MFARegistrationError)
        }
    }
    
    /// This test ensures the static display name is returned for each factor.
    func testFactorInfoDisplayName() throws {
        // Given
        var factorType: [MFA.FactorType] = [MFA.FactorType]()
        
        // Where
        factorType.append(FactorType.face(FaceFactorInfo(id: UUID(), name: "Face", algorithm: .sha512)))
        factorType.append(FactorType.fingerprint(FingerprintFactorInfo(id: UUID(), name: "Fingerprint", algorithm: .sha512)))
        factorType.append(FactorType.userPresence(UserPresenceFactorInfo(id: UUID(), name: "User presence", algorithm: .sha512)))
        factorType.append(FactorType.totp(TOTPFactorInfo(with: "TOTP", digits: 8, algorithm: .sha1, period: 6)))
        factorType.append(FactorType.hotp(HOTPFactorInfo(with: "HOTP", digits: 6, algorithm: .sha1, counter: 0)))
        
        
        // Then
        factorType.forEach { factor in
            if let info = factor.valueType as? FaceFactorInfo {
                XCTAssertTrue(info.displayName == "Face ID")
            }
            if let info = factor.valueType as? FingerprintFactorInfo {
                XCTAssertTrue(info.displayName == "Touch ID")
            }
            if let info = factor.valueType as? UserPresenceFactorInfo {
                XCTAssertTrue(info.displayName == "User presence")
            }
            if let info = factor.valueType as? TOTPFactorInfo {
                XCTAssertTrue(info.displayName == "Time-based one-time password (TOTP)")
            }
            if let info = factor.valueType as? HOTPFactorInfo {
                XCTAssertTrue(info.displayName == "HMAC-based one-time password (HOTP)")
            }
        }
    }
    
    /// This test ensures the static display name is returned for each factor.
    func testFactorTypeDisplayName() throws {
        // Given, Where
        let face = FactorType.face(FaceFactorInfo(id: UUID(), name: "Face", algorithm: .sha512))
        let fingerprint = FactorType.fingerprint(FingerprintFactorInfo(id: UUID(), name: "Fingerprint", algorithm: .sha512))
        let userPresence = FactorType.userPresence(UserPresenceFactorInfo(id: UUID(), name: "User presence", algorithm: .sha512))
        let totp = FactorType.totp(TOTPFactorInfo(with: "TOTP", digits: 8, algorithm: .sha1, period: 6))
        let hotp = FactorType.hotp(HOTPFactorInfo(with: "HOTP", digits: 6, algorithm: .sha1, counter: 0))
        
        // Then
        XCTAssertTrue(face.displayName == "Face ID")
        XCTAssertTrue(fingerprint.displayName == "Touch ID")
        XCTAssertTrue(userPresence.displayName == "User presence")
        XCTAssertTrue(totp.displayName == "Time-based one-time password (TOTP)")
        XCTAssertTrue(hotp.displayName == "HMAC-based one-time password (HOTP)")
    }
    
    /// This test ensures the static id is returned for each factor.
    func testFactorTypeId() throws {
        // Given, Where
        let id = UUID()
        let face = FactorType.face(FaceFactorInfo(id: id, name: "Face", algorithm: .sha512))
        let fingerprint = FactorType.fingerprint(FingerprintFactorInfo(id: id, name: "Fingerprint", algorithm: .sha512))
        let userPresence = FactorType.userPresence(UserPresenceFactorInfo(id: id, name: "User presence", algorithm: .sha512))
        
        // Then
        XCTAssertTrue(face.id == id)
        XCTAssertTrue(fingerprint.id == id)
        XCTAssertTrue(userPresence.id == id)
    }
}
