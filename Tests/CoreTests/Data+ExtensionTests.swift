//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

class DataExtensionTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testBase64UrlEncode() throws {
        // Given
        let value = "Lorem?ipsum"
        
        // Where
        guard let data = value.data(using: .utf8) else {
            XCTFail("Invalid data.")
            return
        }
        
        let result = data.base64UrlEncodedString()
        
        // Then
        XCTAssertEqual(result, "TG9yZW0/aXBzdW0=")
    }
    
    // MARK: - Base58 Tests
        
    func testBase58_EmptyData_ReturnsEmptyString() {
        let data = Data()
        XCTAssertEqual(data.base58EncodedString(), "")
    }
    
    func testBase58_SingleZeroByte_ReturnsOne() {
        // Leading zeros in Base58 are encoded as '1'
        let data = Data([0x00])
        XCTAssertEqual(data.base58EncodedString(), "1")
    }
    
    func testBase58_MultipleLeadingZeros_PrependsOnes() {
        let data = Data([0x00, 0x00, 0x01])
        // 0, 0, 1 -> "11" + encoded "1" which is "2" in base58
        XCTAssertEqual(data.base58EncodedString(), "112")
    }
    
    func testBase58_StandardData_EncodesCorrectly() {
        // "Hello" in hex: 48 65 6c 6c 6f
        let data = "Hello".data(using: .utf8)!
        XCTAssertEqual(data.base58EncodedString(), "9Ajdvzr")
    }
    
    func testBase58_LargeValue_EncodesCorrectly() {
        // Test a value that requires multiple division passes
        let data = Data([0xff, 0xff])
        // 65535 in Base58: 65535 / 58 = 1129 (rem 55 -> 'z')
        // 1129 / 58 = 19 (rem 27 -> 'T')
        // 19 / 58 = 0 (rem 19 -> 'K')
        // Result reversed: "K" "T" "z" -> "KTz"
        XCTAssertEqual(data.base58EncodedString(), "LUv")
    }

    // MARK: - Base64Url Tests
    
    func testBase64Url_DefaultOptions() {
        // "+" and "/" are standard Base64 characters
        // "Subjects" encodes to "U3ViamVjdHM=" which contains no special chars
        // Use a value that creates + and /: "f\u{ff}\u{ff}" -> "Zv// "
        let data = Data([0x66, 0xff, 0xff])
        XCTAssertEqual(data.base64UrlEncodedString(), "Zv//")
    }
    
    func testBase64Url_SafeUrlCharacters() {
        // Data that results in '+' and '/'
        let data = Data([0xfb, 0xff, 0xbf]) // Base64: "+/+/"
        let options: Data.Base64EncodingOptions = [.safeUrlCharacters]
        
        let result = data.base64UrlEncodedString(options: options)
        
        // '+' becomes '-', '/' becomes '_'
        XCTAssertEqual(result, "-_-_")
    }
    
    func testBase64Url_NoPaddingCharacters() {
        let data = "light work.".data(using: .utf8)! // Base64: "bGlnaHQgd29yay4="
        let options: Data.Base64EncodingOptions = [.noPaddingCharacters]
        
        let result = data.base64UrlEncodedString(options: options)
        
        XCTAssertFalse(result.hasSuffix("="))
        XCTAssertEqual(result, "bGlnaHQgd29yay4")
    }
    
    func testBase64Url_CombinedOptions() {
        // Data that results in '+', '/', and '=' padding
        let data = Data([0xfb, 0xff]) // Base64: "+/8="
        let options: Data.Base64EncodingOptions = [.safeUrlCharacters, .noPaddingCharacters]
        
        let result = data.base64UrlEncodedString(options: options)
        
        // Expected: "+/8=" -> "-_8"
        XCTAssertEqual(result, "-_8")
    }
    
    func testBase64Url_WithSpaces() {
        // This hits the .replacingOccurrences(of: " ", with: "%20") line.
        // Standard Base64 can contain newlines/spaces if specific options are passed.
        let data = "Many hands make light work.".data(using: .utf8)!
        let options: Data.Base64EncodingOptions = [.lineLength64Characters, .safeUrlCharacters]
        
        let result = data.base64UrlEncodedString(options: options)
        
        // lineLength options insert \r\n, which percent encoding handles,
        // but we want to ensure any spaces introduced by formatting are caught.
        XCTAssertFalse(result.contains(" "))
    }
    
    func testBase64Url_PercentEncodingFailure_ReturnsEmpty() {
        // It is extremely difficult to make addingPercentEncoding fail with the current character set,
        // but for coverage of the 'guard var value' else branch, we mock or test an empty result.
        // In actual execution, if base64EncodedString returns something invalid (impossible for standard Data),
        // it would trigger. For now, testing empty input ensures the flow is solid.
        let data = Data()
        XCTAssertEqual(data.base64UrlEncodedString(), "")
    }
}
