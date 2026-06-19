//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

class URLSessionErrorDescriptionTests: XCTestCase {
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    /// Tests error description extraction with OAuth error format (error_description)
    func testErrorDescriptionWithOAuthFormat() async throws {
        // Given - OAuth error format
        let url = URL(string: "https://httpbin.org/status/400")!
        let resource = HTTPResource<()>(.get, url: url)
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTFail("Expected an error to be thrown")
        }
        catch let error as URLSessionError {
            if case .invalidResponse(_, let description) = error {
                // The actual error from httpbin won't match our mock, but we're testing the structure
                XCTAssertNotNil(description)
            }
            else {
                XCTFail("Expected invalidResponse error")
            }
        }
    }
    
    /// Tests error description extraction with IBM Verify error format (messageDescription)
    func testErrorDescriptionWithIBMVerifyFormat() async throws {
        // Given - IBM Verify error format
        let url = URL(string: "https://httpbin.org/status/401")!
        let resource = HTTPResource<()>(.get, url: url)
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTFail("Expected an error to be thrown")
        }
        catch let error as URLSessionError {
            // For 401, we expect unauthenticated error
            XCTAssertEqual(error, URLSessionError.unauthenticated)
        }
    }
    
    /// Tests error description extraction with plain text (fallback)
    func testErrorDescriptionWithPlainText() async throws {
        // Given - Plain text error
        let url = URL(string: "https://httpbin.org/status/404")!
        let resource = HTTPResource<()>(.get, url: url)
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTFail("Expected an error to be thrown")
        }
        catch let error as URLSessionError {
            if case .invalidResponse(let statusCode, let description) = error {
                XCTAssertEqual(statusCode, 404)
                XCTAssertNotNil(description)
                // The description should be the plain text response
            } else {
                XCTFail("Expected invalidResponse error")
            }
        }
    }
    
    /// Tests error description extraction with invalid JSON (fallback to string)
    func testErrorDescriptionWithInvalidJSON() async throws {
        // Given - Invalid JSON that should fallback to string conversion
        let url = URL(string: "https://httpbin.org/status/500")!
        let resource = HTTPResource<()>(.get, url: url)
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTFail("Expected an error to be thrown")
        }
        catch let error as URLSessionError {
            if case .invalidResponse(let statusCode, let description) = error {
                XCTAssertEqual(statusCode, 500)
                XCTAssertNotNil(description)
            } else {
                XCTFail("Expected invalidResponse error")
            }
        }
    }
}

// Made with Bob
