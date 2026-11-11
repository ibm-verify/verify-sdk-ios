//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import XCTest
@testable import FIDO2

class COSETests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testCreateCOSEKeyEC2() throws {
        // Given
        let xCoord =  "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d".hexadecimal
        let yCoord = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c".hexadecimal
        
        // When
        let result = COSEKeyEC2(alg: COSEAlgorithmIdentifier.es256.rawValue,
            crv: 1,
            xCoord: Array(xCoord),
            yCoord: Array(yCoord)
        )

        // Then
        XCTAssertNotNil(result)
    }

    func testCOSEKeyEC2Bytes() throws {
        // Given
        let xCoord =  "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d".hexadecimal
        let yCoord = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c".hexadecimal
        
        // When
        let result = COSEKeyEC2(alg: COSEAlgorithmIdentifier.es256.rawValue,
            crv: 1,
            xCoord: Array(xCoord),
            yCoord: Array(yCoord)
        )
        
        // Then
        XCTAssertNotNil(result.bytes)
    }
    
    func testeCOSEKeyEC2ToBytes() throws {
        // Given
        let xCoord =  "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d".hexadecimal
        let yCoord = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c".hexadecimal
        
        // When
        let result = COSEKeyEC2(alg: COSEAlgorithmIdentifier.es256.rawValue,
            crv: 1,
            xCoord: Array(xCoord),
            yCoord: Array(yCoord)
        )

        // Then
        XCTAssertNotNil(result.toBytes())
    }

    func testCOSEKeyAKPBytes() throws {
        // Given
        let pub = [UInt8](repeating: 0xAB, count: 1952)

        // When
        let result = COSEKeyAKP(alg: COSEAlgorithmIdentifier.mldsa65.rawValue, pub: pub)

        // Then: map(3), kty(1)=7, alg(3)=-49, pub(-1)=bstr
        let bytes = result.bytes
        XCTAssertEqual(bytes.first, 0xA3)
        XCTAssertEqual(bytes.count, result.toBytes().count)
        XCTAssertNotNil(Data(bytes).range(of: Data(pub)))
    }
}

extension String {
    var hexadecimal: Data {
        var data = Data(capacity: count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            let num = UInt8(byteString, radix: 16)!
            data.append(num)
        }
        
        guard data.count > 0 else {
            return Data()
        }
        
        return data
    }
}
