//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
@testable import MFA

class OTPAuthenticatorTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    // MARK: - OTP Autenticator Digits

    /// Test to create an TOTP authenticator from a QR code that assigns default digit value of 6.
    func testCreateTOTPFromQRCodeDefaultDigits() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.digits, 6)
    }
    
    /// Test to create an TOTP authenticator from a QR code where an invalid value is presented.
    func testCreateTOTPFromQRCodeDigitsInvalid() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=68"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)
        
        // Then
        XCTAssertNil(result)
    }
    
    /// Test to create an TOTP authenticator from a QR code that assigns valid digit value of 6.
    func testCreateTOTPFromQRCodeDigits6() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.digits, 6)
    }
    
    /// Test to create an TOTP authenticator from a QR code that assigns valid digit value of 8.
    func testCreateTOTPFromQRCodeDigits8() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=8"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.digits, 8)
    }
    
    /// Test to create an TOTP authenticator that assigns default digit value of 6 when an invalid value is presented.
    func testCreateTOTPDigitsInvalid() throws {
        // Given
        let value = TOTPFactorInfo(with: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", digits: 65)
        
        // When
        let result = OTPAuthenticator(with: "ACME Co", accountName: "john.doe@email.com", factor: value)
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.digits, 65)
    }
    
    /// Test to create an HOTP authenticator that assigns default digit value of 6 when an invalid value is presented.
    func testCreateHOTPDigitsInvalid() throws {
        // Given
        let value = HOTPFactorInfo(with: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", digits: 65)
        
        // When
        let result = OTPAuthenticator(with: "ACME Co", accountName: "john.doe@email.com", factor: value)
        
        // Then
        let factor = result.allowedFactors[0].valueType as! HOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.digits, 65)
    }
    
    // MARK: - OTP Autenticator Algorithm
    
    /// Test to create an TOTP authenticator from a QR code that assigns default algorithm of sha1.
    func testCreateTOTPFromQRCodeDefaultAlgorithm() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
    }
    
    /// Test to create an TOTP authenticator from a QR code that assigns algorithm of sha256.
    func testCreateTOTPFromQRCodeAlgorithmSHA256() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha256)
    }
    
    /// Test to create an TOTP authenticator from a QR code that assigns algorithm of sha384
    func testCreateTOTPFromQRCodeAlgorithmSHA384() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA384"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha384)
    }
    
    /// Test to create an TOTP authenticator from a QR code that assigns algorithm of sha512.
    func testCreateTOTPFromQRCodeAlgorithmSHA512() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA512"
        
        // When
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha512)
    }
    
    /// Test to create an TOTP authenticator from a QR code that assigns default algorithm of sha1 where an invalid algorithm.
    func testCreateTOTPFromQRCodeAlgorithmInvalid() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1024"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)
        
        // Then
        XCTAssertNil(result)
    }
    
    // MARK: - OTP Autenticator Initializers
    
    /// Test to create an HOTP authenticator with all parameters.
    func testCreateHOTP() throws {
        // Given
        let value = HOTPFactorInfo(with: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", digits: 6, algorithm: .sha1, counter: 1)
        
        //When
        let result = OTPAuthenticator(with: "ACME Co", accountName: "john.doe@email.com", factor: value)
            
        // Then
        let factor = result.allowedFactors[0].valueType as! HOTPFactorInfo
       
        // Then
        XCTAssertEqual(result.serviceName, "ACME Co")
        XCTAssertEqual(result.accountName, "john.doe@email.com")
        XCTAssertEqual(factor.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
        XCTAssertEqual(factor.digits, 6)
        XCTAssertEqual(factor.counter, 1)
    }
    
    /// Test to create an HOTP authenticator with minimum parameters assigning default values.
    func testCreateMinimunHOTP() throws {
        // Given
        let value = HOTPFactorInfo(with: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        
        // When
        let result = OTPAuthenticator(with: "ACME Co", accountName: "john.doe@email.com", factor: value)
            
        // Then
        let factor = result.allowedFactors[0].valueType as! HOTPFactorInfo
       
        // Then
        XCTAssertEqual(result.serviceName, "ACME Co")
        XCTAssertEqual(result.accountName, "john.doe@email.com")
        XCTAssertEqual(factor.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
        XCTAssertEqual(factor.digits, 6)
        XCTAssertEqual(factor.counter, 1)
    }
    
    /// Test to create an TOTP authenticator with minimum parameters assigning default values.
    func testCreateMinimunTOTP() throws {
        // Given
        let value = TOTPFactorInfo(with: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        
        // When
        let result = OTPAuthenticator(with: "ACME Co", accountName: "john.doe@email.com", factor: value)
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
       
        // Then
        XCTAssertEqual(result.serviceName, "ACME Co")
        XCTAssertEqual(result.accountName, "john.doe@email.com")
        XCTAssertEqual(factor.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
        XCTAssertEqual(factor.digits, 6)
        XCTAssertEqual(factor.period, 30)
    }
    
    /// Test to create an TOTP authenticator from an invalid QR code.
    func testCreateTOTPFromQRCodeInvalid() throws {
        // Given
        let qrScan = "otpauth://otp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)
            
        // Then
        XCTAssertNil(result)
    }
    
    /// Test to create an TOTP authenticator from an invalid QR code secret parameter.
    func testCreateTOTPFromQRCodeInvalidSecret() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)
            
        // Then
        XCTAssertNil(result)
    }
    
    /// Test to create an TOTP authenticator from a QR code where the account name if equal to the issuer.
    func testCreateTOTPFromQRCodeUsernameFromIssuer() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA1&digits=6&period=30"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
        
        // Then
        XCTAssertEqual(result.serviceName, result.accountName)
    }
    
    /// Test to create an TOTP authenticator from an invalid QR code issuer parameter.
    func testCreateTOTPFromQRCodeInvalidIssuer() throws {
        // Given
        let qrScan = "otpauth://totp/?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA1&digits=6&period=30"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)
            
        // Then
        XCTAssertNil(result)
    }
    
    /// Test to create an TOTP authenticator from a QR code with all parameters.
    func testCreateTOTPFromQRCode() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
        
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(result.serviceName, "ACME Co")
        XCTAssertEqual(result.accountName, "john.doe@email.com")
        XCTAssertEqual(factor.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
        XCTAssertEqual(factor.digits, 6)
        XCTAssertEqual(factor.period, 30)
    }
    
    /// Test to create an TOTP authenticator from a QR code within valid period range.
    func testCreateTOTPFromQRCodePeriodValidRange() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=10"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.period, 10)
    }
    
    /// Test to create an TOTP authenticator from a QR code with invalid period assigning the default value.
    func testCreateTOTPInvalidPeriod() throws {
        // Given
        let value = TOTPFactorInfo(with: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", period: 347)
        
        // When
        let result = OTPAuthenticator(with: "ACME Co", accountName: "john.doe@email.com", factor: value)
            
        // Then
        let factor = result.allowedFactors[0].valueType as! TOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.period, 30)
    }
    
    /// Test to create an TOTP authenticator from a QR code with invalid low period.
    func testCreateTOTPFromQRCodePeriodInvalidLowRange() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=8"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)
            
        // Then
        XCTAssertNil(result, "Period value is below the accepted range.")
    }
    
    /// Test to create an TOTP authenticator from a QR code with invalid high period.
    func testCreateTOTPFromQRCodePeriodInvalidHighRange() throws {
        // Given
        let qrScan = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=304"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)
            
        // Then
        XCTAssertNil(result, "Period value is above the accepted range.")
    }
    
    /// Test to create an HOTP authenticator and change the counter to an invalid value.
    func testCreateHOTPIncrementCounter() throws {
        // Given
        var factor = HOTPFactorInfo(with: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", counter: 1)
        
        // When
        let _ = factor.generatePasscode()
        XCTAssertEqual(factor.counter, 2)
    }
    
    /// Test to create an HOTP authenticator with an invalid counter value.
    func testCreateHOTPCounterInvalid() throws {
        // Given, When
        let factor = HOTPFactorInfo(with: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", counter: -20)
        
        // Then
        XCTAssertEqual(factor.counter, 1)
    }
    
    /// Test to create an HOTP authenticator from a QR code with default counter value of 1.
    func testCreateHOTPFromQRCode() throws {
        // Given
        let qrScan = "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
            
        // Then
        let factor = result.allowedFactors[0].valueType as! HOTPFactorInfo
        
        // Then
        XCTAssertEqual(result.serviceName, "ACME Co")
        XCTAssertEqual(result.accountName, "john.doe@email.com")
        XCTAssertEqual(factor.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
        XCTAssertEqual(factor.digits, 6)
    }
    
    /// Test to create an HOTP authenticator from a QR code with a custom counter.
    func testCreateHOTPFromQRCodeCounter() throws {
        // Given
        let qrScan = "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&counter=60"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)!
        
        // Then
        let factor = result.allowedFactors[0].valueType as! HOTPFactorInfo
        
        // Then
        XCTAssertEqual(factor.counter, 60)
    }
    
    // MARK: - OTP Autenticator Codable
    
    /// Test to encode an OTP authenticator to JSON.
    func testOTPEncodeJSON() throws {
        // Given
        let qrScan = "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6"
        
        // When
        let result = OTPAuthenticator(fromQRScan: qrScan)
            
        // Then
        let data = try? JSONEncoder().encode(result)
        let encodedJson = String(decoding: data!, as: UTF8.self)

        // Then
        XCTAssertNotNil(encodedJson)
    }
    
    /// Test to create an OTP authenticator from a JSON.
    func testOTPDecodeJSON() throws {
        // Given
        let json = """
         {
            "allowedFactors":[
               {
                  "hotp":{
                     "secret":"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                     "id":"5085FF89-8322-4F49-ABFC-64B18A85BFC6",
                     "digits":6,
                     "counter":5,
                     "algorithm":"sha1"
                  }
               }
            ],
            "id":"A6C8EF51-6874-4BE0-9C23-4365D518E242",
            "serviceName":"ACME Co",
            "accountName":"john.doe@email.com"
         }
         """
        
        // When
        let result = try JSONDecoder().decode(OTPAuthenticator.self, from: json.data(using: .utf8)!)
            
        // Then
        let factor = result.allowedFactors[0].valueType as! HOTPFactorInfo
        
        XCTAssertEqual(result.serviceName, "ACME Co")
        XCTAssertEqual(result.accountName, "john.doe@email.com")
        XCTAssertEqual(factor.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
        XCTAssertEqual(factor.digits, 6)
        XCTAssertEqual(factor.counter, 5)
    }
    
    /// Test to create an OTP authenticator from a JSON.
    func testOTPLowEntropyDecodeJSON() throws {
        // Given
        let json = """
         {
            "allowedFactors":[
               {
                  "hotp":{
                     "secret":"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                     "id":"5085FF89-8322-4F49-ABFC-64B18A85BFC6",
                     "digits":4,
                     "counter":5,
                     "algorithm":"sha1"
                  }
               }
            ],
            "id":"A6C8EF51-6874-4BE0-9C23-4365D518E242",
            "serviceName":"ACME Co",
            "accountName":"john.doe@email.com"
         }
         """
        
        // When
        let result = try JSONDecoder().decode(OTPAuthenticator.self, from: json.data(using: .utf8)!)
            
        // Then
        let factor = result.allowedFactors[0].valueType as! HOTPFactorInfo
        
        XCTAssertEqual(result.serviceName, "ACME Co")
        XCTAssertEqual(result.accountName, "john.doe@email.com")
        XCTAssertEqual(factor.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
        XCTAssertEqual(factor.digits, 4)
        XCTAssertEqual(factor.counter, 5)
    }
    
    /// Test to create an HOTP authenticator from a JSON then test invalid and default counter values.
    func testOTPDecodeJSONUpdateCounter() throws {
        // Given
       let json = """
        {
           "allowedFactors":[
              {
                 "hotp":{
                    "secret":"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                    "id":"5085FF89-8322-4F49-ABFC-64B18A85BFC6",
                    "digits":6,
                    "counter":5,
                    "algorithm":"sha1"
                 }
              }
           ],
           "id":"A6C8EF51-6874-4BE0-9C23-4365D518E242",
           "serviceName":"ACME Co",
           "accountName":"john.doe@email.com"
        }
        """
        
        // When
        let result = try JSONDecoder().decode(OTPAuthenticator.self, from: json.data(using: .utf8)!)
            
        // Then
        var factor = result.allowedFactors[0].valueType as! HOTPFactorInfo
        XCTAssertEqual(factor.counter, 5)
        
        // Then
        let _ = factor.generatePasscode()
        
        // Then
        XCTAssertEqual(result.serviceName, "ACME Co")
        XCTAssertEqual(result.accountName, "john.doe@email.com")
        XCTAssertEqual(factor.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(factor.algorithm, HashAlgorithmType.sha1)
        XCTAssertEqual(factor.digits, 6)
        XCTAssertEqual(factor.counter, 6)
    }
    
    // MARK: - OTP Autenticator Create
    
    // Test to encode generate OTP from an invalid secret
    func testInvalidSecret() throws {
        // Given
        var factor = TOTPFactorInfo(with: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0", period: 347)
        
        // When
        let result = factor.generatePasscode()
      
        // Then
        XCTAssertEqual(result, "")
    }
    
    /// Test to generate 5 OTP codes using HOTP with starting counter 1 with SHA1
    /// ```
    /// oathtool --hotp --base32 JBSWY3DPEHPK3PXP  -w 5 -c 1
    /// ```
    func testGenerateHOTPCodeSHA1() throws {
        // Given
        let values = ["996554","602287","143627","960129","768897"]
        
        var factor = HOTPFactorInfo(with: "JBSWY3DPEHPK3PXP", counter: 1)
        
        // When
        for i in 0...4 {
            XCTAssertEqual(factor.counter, i + 1)
            
            let result = factor.generatePasscode()
        
            // Then
            XCTAssertFalse(result.isEmpty)
            XCTAssertEqual(result, values[i])
        }
    }
    
    /// Test to generate 5 OTP codes using HOTP with starting counter 1 with SHA256
    func testGenerateHOTPCodeSHA256() throws {
        // Given
        let values = ["344551","730792","653637","766270","302147"]
        
        var factor = HOTPFactorInfo(with: "JBSWY3DPEHPK3PXP", algorithm: .sha256, counter: 1)
        
        // When
        for i in 0...4 {
            XCTAssertEqual(factor.counter, i + 1)
            
            let result = factor.generatePasscode()
        
            // Then
            XCTAssertFalse(result.isEmpty)
            XCTAssertEqual(result, values[i])
        }
    }
    
    /// Test to generate 5 OTP codes using HOTP with starting counter 1 with SHA256
    func testGenerateHOTPCodeSHA384() throws {
        // Given
        let values = ["302495","982841","470311","288591","644699"]
        
        var factor = HOTPFactorInfo(with: "JBSWY3DPEHPK3PXP", algorithm: .sha384, counter: 1)
        
        // When
        for i in 0...4 {
            XCTAssertEqual(factor.counter, i + 1)
            
            let result = factor.generatePasscode()
        
            // Then
            XCTAssertFalse(result.isEmpty)
            XCTAssertEqual(result, values[i])
        }
    }
    
    /// Test to generate 5 OTP codes using HOTP with starting counter 1 with SHA256
    func testGenerateHOTPCodeSHA512() throws {
        // Given
        let values = ["439887","644671","829955","708699","923460"]
        
        var factor = HOTPFactorInfo(with: "JBSWY3DPEHPK3PXP", algorithm: .sha512, counter: 1)
        
        // When
        for i in 0...4 {
            XCTAssertEqual(factor.counter, i + 1)
            
            let result = factor.generatePasscode()
        
            // Then
            XCTAssertFalse(result.isEmpty)
            XCTAssertEqual(result, values[i])
        }
    }
}
