//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
import Authentication
import Core
import CryptoKit
@testable import MFA

class CloudAuthenticatorTests: XCTestCase {

    let urlBase = "https://sdk.verify.ibm.com"
    
    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(MockURLProtocol.self)
    }

    override func tearDown() {
        super.tearDown()
        URLProtocol.unregisterClass(MockURLProtocol.self)
    }

    /// This test initiates, enrolls and finalizes an authenticator, then encodes to JSON.
    func testInitiateAndEnrollThenEncodingTest() async throws {
        // Given
        let refreshUrl = URL(string: "\(urlBase)/v1.0/authenticators/registration?metadataInResponse=false")!
        MockURLProtocol.urls[refreshUrl] = MockHTTPResponse(response: HTTPURLResponse(url: refreshUrl, statusCode: 200, httpVersion: nil, headerFields: nil)!, fileResource: "cloud.refresh")
        
        // When
        let authenticator = try await CloudRegistrationProviderTests().testFinalizeRegistration()
        
        // Then
        XCTAssertNotNil(authenticator)
        
        // Then
        guard let authenticator = authenticator as? CloudAuthenticator else {
            throw CloudRegistrationError.failedToParse
        }
        
        // Then
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted

        let data = try encoder.encode(authenticator)
        print(String(data: data, encoding: .utf8)!)
        
        // Then
        XCTAssertNotNil(data)
    }
    
    /// This test decodes an authenticator and checks values are the same.
    func testDecodingTest() async throws -> CloudAuthenticator {
        // Given, When
        var data: Data {
            get {
                let url = Bundle.module.url(forResource: "cloud.authenticator", withExtension: "json", subdirectory: "Files")!
                return try! Data(contentsOf: url)
            }
        }
        
        // Then
        let decoder = JSONDecoder()
        return try decoder.decode(CloudAuthenticator.self, from: data)
    }
    
    /// This test decodes an authenticator and adds a certificate for pinning.
    func testUpdateAuthenticatorEncodeTest() async throws {
        // Given, When
        var authenticator = try await testDecodingTest()
        
        // Then
        XCTAssertNotNil(authenticator)
        
        // Then
        authenticator.accountName = "Jane Citizen"
        authenticator.publicKeyCertificate = "AAAAB3NzaC1yc2EAAAADAQABAAACAQDExEer5JtuAL8Qd8n4pt7kq0a1Akb2XSEMDy01MBTFYxbXe/PVMtTwf2Q+v/mSTWBeiYuQZlfFJE4LPmOFg+5LfevfxAHHSUGGjxzn8dVABejHEo/uPymCqO9grOk2AQRpwSgdrLrvnxWh+AWmLm9ZTmu5rcBSrej0RNEI6/ACWGdR4690VhytNd6NRKz2zEAJCXAfXFgzNOdtnhaTQiHGrJvp8ASQwRfDpMPY5C8W8sLhhQ4g0rKsY7IyUMADyBO4spKJbAkA7oD1LoOOJ1vj6rWmt0H4wNTiDxqIcem6weM7enkw9lSdRp7ELzVB7Yjj6BjcClZsqntzHs4Km4xSqqzuKDdCuc5a6Zjs1kFtL8KH8VrP9lfMOFo4A6/43ycy2vtVDQ83UFFxeCjJNdVbzct0r+1MDc1rKoKY5XAu+jHHjzACW3ioYxUk5mI7scHjW+xltCx8fmLn0rQjUYQgcMUnw41haCrM4eSKh7HhaDKsbLxOae5FqO7xb6bUFKUJFHtpaeNKbu1X4XuWDPM0f21B7IUElDEYIP7lgBaoKbGYItzuIYzWYHnlPtYJ11fMnaJaXLEw7/H33yiIUEx0n5s52FruxUtFy2NlGh3O4PXBA9BdU0dxVyV+qM8Hzk4ys6hIBYaN/4GJiSTdLUiEhIKoVdDhOIeC7nIOA29/PQ=="
        
        // Then
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted

        let data = try encoder.encode(authenticator)
        print(String(data: data, encoding: .utf8)!)
        
        // Then
        XCTAssertNotNil(data)
    }
    
    /// This test gets the array of allowed factors.
    func testAuthenticatorFactorsTest() async throws {
        // Given, When
        let authenticator = try await testDecodingTest()
        
        // Then
        XCTAssertNotNil(authenticator)
        
        // Then
        authenticator.allowedFactors.forEach { print($0.valueType.id) }
        
        // Then
        XCTAssertEqual(authenticator.allowedFactors.count, 1)
    }
}
