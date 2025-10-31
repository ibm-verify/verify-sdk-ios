//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
import CryptoKit
@testable import MFA

class OTPGeneratorTests: XCTestCase {
    let secret = "JBSWY3DPEHPK3PXP"
    
        override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // MARK: - Generate Code with SHA1
    func testGenerateCodeSHA1Digits6() throws {
        // Given
        let values = ["282760", "996554", "602287", "143627", "960129", "768897", "883951","449891", "964230", "924769"]
        let factor = TOTPFactorInfo(with: secret, digits: 6)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 6)
            XCTAssertEqual(result, values[i])
        }
    }
    
    /// Test the OTP calculation based on a time interval from 01-01-1970 00:00:00 UTC
    /// ```
    /// oathtool --totp --base32 JBSWY3DPEHPK3PXP  -w 5 --now '1970-01-01 00:00:00 UTC' -s 5
    /// ```
    func testGenerateCodeSHA1Digits6TOTP() throws {
        // Given
        let values = ["282760", "996554", "602287", "143627", "960129"]
        let factor = TOTPFactorInfo(with: secret, digits: 6)
        let period = TimeInterval(5)
        
        let isoDate = "1970-01-01T00:00:00+0000"
        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
        var date = dateFormatter.date(from: isoDate)!
        
        // When
        for i in 0...4 {
            // Get the timer interval for the date since 01-01-1970 00:00:00 UTC
            let timeInterval: TimeInterval = date.timeIntervalSince1970
            let value = UInt64(timeInterval / period)
            
            // When
            let result = factor.generatePasscode(from: value)
            
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 6)
            XCTAssertEqual(result, values[i])
            
            // Increment the date since 01-01-1970 00:00:00 UTC by 5 seconds.
            date = date.advanced(by: TimeInterval(5))
        }
    }
    
    func testGenerateCodeSHA1Digits8() throws {
        // Given
        let values = ["63282760", "41996554", "88602287", "91143627", "05960129", "38768897", "68883951", "34449891", "20964230", "39924769"]
        let factor = TOTPFactorInfo(with: secret, digits: 8)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 8)
            XCTAssertEqual(result, values[i])
        }
    }
    
    // MARK: - Generate Code with SHA256
    func testGenerateCodeSHA256Digits6() throws {
        // Given
        let values = ["023015", "344551", "730792", "653637", "766270", "302147", "787195", "346239", "349119",  "332375"]
        let factor = TOTPFactorInfo(with: secret, digits: 6, algorithm: .sha256)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 6)
            XCTAssertEqual(result, values[i])
        }
    }
    
    func testGenerateCodeSHA256Digits8() throws {
        // Given
        let values = ["96023015", "36344551", "52730792", "92653637", "49766270", "92302147", "78787195", "02346239", "45349119", "69332375"]
        let factor = TOTPFactorInfo(with: secret, digits: 8, algorithm: .sha256)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 8)
            XCTAssertEqual(result, values[i])
        }
    }
    
    // MARK: - Generate Code with SHA384
    func testGenerateCodeSHA384Digits6() throws {
        // Given
        let values = ["336774", "302495", "982841", "470311", "288591", "644699", "284645", "856837", "516982", "127118"]
        let factor = TOTPFactorInfo(with: secret, digits: 6, algorithm: .sha384)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 6)
            XCTAssertEqual(result, values[i])
        }
    }
    
    func testGenerateCodeSHA384Digits8() throws {
        // Given
        let values = ["90336774", "24302495", "91982841", "98470311", "83288591", "02644699", "93284645", "33856837", "44516982", "18127118"]
        let factor = TOTPFactorInfo(with: secret, digits: 8, algorithm: .sha384)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 8)
            print("Index \(i): \(result)")
            XCTAssertEqual(result, values[i])
        }
    }
    
    // MARK: - Generate Code with SHA512
    func testGenerateCodeSHA512Digits6() throws {
        // Given
        let values = ["582788", "439887", "644671", "829955", "708699", "923460", "673439", "975035", "131699", "099912"]
        let factor = TOTPFactorInfo(with: secret, digits: 6, algorithm: .sha512)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 6)
            XCTAssertEqual(result, values[i])
        }
    }
    
    func testGenerateCodeSHA512Digits8() throws {
        // Given
        let values = ["46582788", "31439887", "50644671", "07829955", "85708699", "76923460", "70673439", "11975035", "46131699", "56099912"]
        let factor = TOTPFactorInfo(with: secret, digits: 8, algorithm: .sha512)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 8)
            XCTAssertEqual(result, values[i])
        }
    }
    
    func testGenerateCodeSHA512Digits2LowEntropy() throws {
        // Given
        let values = ["88", "87", "71", "55", "99", "60", "39", "35", "99", "12"]
        let factor = TOTPFactorInfo(with: secret, digits: 2, algorithm: .sha512)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 2)
            XCTAssertEqual(result, values[i])
        }
    }
    
    func testGenerateCodeSHA512Digits3LowEntropy() throws {
        // Given
        let values = ["788", "887", "671", "955", "699", "460", "439", "035", "699", "912"]
        let factor = TOTPFactorInfo(with: secret, digits: 3, algorithm: .sha512)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 3)
            XCTAssertEqual(result, values[i])
        }
    }
    
    func testGenerateCodeSHA512Digits4LowEntropy() throws {
        // Given
        let values = ["2788", "9887", "4671", "9955", "8699", "3460", "3439", "5035", "1699", "9912"]
        let factor = TOTPFactorInfo(with: secret, digits: 4, algorithm: .sha512)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 4)
            XCTAssertEqual(result, values[i])
        }
    }
    
    func testGenerateCodeSHA512Digits5LowEntropy() throws {
        // Given
        let values = ["82788", "39887", "44671", "29955", "08699", "23460", "73439", "75035", "31699", "99912"]
        let factor = TOTPFactorInfo(with: secret, digits: 5, algorithm: .sha512)
        
        // When
        for i in 0...9 {
            let result = factor.generatePasscode(from: UInt64(i))
        
            // Then
            XCTAssertNotNil(result)
            XCTAssertEqual(result.count, 5)
            XCTAssertEqual(result, values[i])
        }
    }
    
    func testDigits0AssignDefault() throws {
        // Given
        let factor = TOTPFactorInfo(with: secret, digits: 0, algorithm: .sha512)
        
        // When, Then
        XCTAssertEqual(factor.digits, 6)
    }
    
    
    func testTimeRemaining() throws {
        // Given
        let value = TOTPFactorInfo.remainingTime(60)
        
        // When, Then
        XCTAssertTrue(value > 0)
    }
}
