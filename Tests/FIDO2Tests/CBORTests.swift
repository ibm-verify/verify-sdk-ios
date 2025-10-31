//
// Copyright contributors to the IBM Verify FIDO2 SDK for iOS project
//

import XCTest
@testable import FIDO2

class CBORTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testCreateCBORReader() {
        // Given
        let bytes = [UInt8]("helloworld".utf8)
        let result = CBORReader(bytes: bytes)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testGetReadSize() {
        // Given
        let bytes = [UInt8]("helloworld".utf8)
        let result = CBORReader(bytes: bytes)
        
        // Then
        XCTAssertEqual(result.getReadSize(), 0)
    }
    
    func testGetRestSize() {
        // Given
        let bytes = [UInt8]("helloworld".utf8)
        let result = CBORReader(bytes: bytes)
        
        // Then
        XCTAssertEqual(result.getRestSize(), 10)
    }
    func testAnyNil() {
        // Given
        let bytes: [UInt8] = []
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny()
        
        // Then
        XCTAssertNil(result)
    }
    
    func testAnyString() {
        // Given
        let bytes = [UInt8]("helloworld".utf8)
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny()
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testAnyInt() {
        // Given
        let bytes: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7]
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny()
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testAnyTrueBit() {
        // Given
        let bytes: [UInt8] = [0xf5]
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny() as! Bool
        
        // Then
        XCTAssertTrue(result)
    }
    
    func testAnyFalseBit() {
        // Given
        let bytes: [UInt8] = [0xf4]
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny() as! Bool
        
        // Then
        XCTAssertFalse(result)
    }
    
    func testAnyNullBit() {
        // Given
        let bytes: [UInt8] = [0xf6]
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny()
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testAnyFloatBit() {
        // Given
        let bytes: [UInt8] = [0xfa, 0x7f, 0x7f, 0xff, 0xff]
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny() as! Float
        
        // Then
        XCTAssertEqual(result, 3.4028234663852886e+38)
    }
    
    func testAnyDoubleBit() {
        // Given
        let bytes: [UInt8] = [0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x91]
        // fb3ff199999999999a
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny() as! Double
        
        // Then
        XCTAssertEqual(result, 1.099999999999998)
    }

    func testAnyHeaderBit() {
        // Given
        let bytes: [UInt8] = [0x0b, 0x11, 0x10, 0x00, 0x00]
        let value = CBORReader(bytes: bytes)
        
        // When
        let result = value.readAny()
        
        // Then
        XCTAssertNotNil(result)
    }

    func testFloat() {
        [(100000.0, "fa47c35000"),
         (3.4028234663852886e+38, "fa7f7fffff")].forEach {
                assertFloat($0.0, $0.1)
        }
    }
    
    func testDouble() {
        [(1.1, "fb3ff199999999999a"),
         (1.0e+300, "fb7e37e43c8800759c"),
         (-4.1, "fbc010666666666666")].forEach {
            assertDouble($0.0, $0.1)
        }
    }
    
    func testString() {
        [("", "60"),
         ("a", "6161"),
         ("IETF", "6449455446"),
         ("\"\\", "62225c"),
         ("\u{00fc}", "62c3bc"),
         ("\u{6c34}", "63e6b0b4"),
         ("\u{00fc}", "62c3bc")].forEach {
            assertString($0.0, $0.1)
        }
    }
    
    func testByteString() {
        [([], "40"),
         ([0x01,0x02,0x03,0x04],"4401020304"),].forEach {
                assertByteString($0.0, $0.1)
        }
    }

    func testBool() {
        [(false, "f4"),
         (true, "f5")].forEach {
            assertBool($0.0, $0.1)
         }
    }
    
    func testInteger() {
        // https://tools.ietf.org/html/rfc7049#appendix-A
        [(0, "00"),
         (1, "01"),
         (10, "0a"),
         (23, "17"),
         (24, "1818"),
         (25, "1819"),
         (100, "1864"),
         (1000, "1903e8"),
         (1000000, "1a000f4240"),
         (1000000000000, "1b000000e8d4a51000"),
         (-1, "20"),
         (-10, "29"),
         (-100, "3863"),
         (-1000, "3903e7")].forEach {
           assertNumber($0.0, $0.1)
        }
    }
    
    func testNull() {
        let writer = CBORWriter().putNull().getResult()
        let bytes = [UInt8]("f6".hexadecimal)
        XCTAssertEqual(writer, bytes)
        
        let reader = CBORReader(bytes: bytes)
        let value: ()? = reader.readNull()
        XCTAssertNotNil(value)
    }
    
    func testArray() {
        let val1: [Int64] = []
        let bytes1 = [UInt8]("80".hexadecimal)
        XCTAssertEqual(CBORWriter().putArray(val1).getResult(), bytes1)
        
        let result1 = CBORReader(bytes: bytes1).readArray()
        XCTAssertEqual(result1!.count, 0)
    
        let val2: [Int64] = [1, 2, 3]
        let bytes2 = [UInt8]("83010203".hexadecimal)
        XCTAssertEqual(CBORWriter().putArray(val2).getResult(), bytes2)
        
        let result2 = CBORReader(bytes: bytes2).readArray()
        
        XCTAssertEqual(result2!.count, 3)
        XCTAssertEqual(result2![0] as! Int64, 1)
        XCTAssertEqual(result2![1] as! Int64, 2)
        XCTAssertEqual(result2![2] as! Int64, 3)
        
        
        let val3: [Int64] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
        let bytes3 = [UInt8]("98190102030405060708090a0b0c0d0e0f101112131415161718181819".hexadecimal)
        
        XCTAssertEqual(CBORWriter().putArray(val3).getResult(), bytes3)
        
        let result3 = CBORReader(bytes: bytes3).readArray()
        XCTAssertEqual(result3!.count, 25)
        XCTAssertEqual(result3![0] as! Int64, 1)
        XCTAssertEqual(result3![24] as! Int64, 25)
    }
    
    func testMap() {
        let val1: [String: String] = [:]
        let bytes1 = [UInt8]("a0".hexadecimal)
        XCTAssertEqual(CBORWriter().putStringKeyMap(val1).getResult(), bytes1)
        
        let result1 = CBORReader(bytes: bytes1).readStringKeyMap()
        XCTAssertEqual(result1!.count, 0)
        
        var val2: [String: Any] = [:]
        let bytes2 = [UInt8]("a26161016162820203".hexadecimal)
        
        val2.updateValue(Int64(1), forKey: "a")
        let val3: [Any] = [Int64(2), Int64(3)]
        val2.updateValue(val3, forKey: "b")
        XCTAssertNotNil(CBORWriter().putStringKeyMap(val2).getResult())
        
        let result2 = CBORReader(bytes: bytes2).readStringKeyMap()
        XCTAssertEqual(result2!.count, 2)
        XCTAssertEqual(result2!["a"] as! Int64, Int64(1))
        
        var val4: [Int: Int64] = [:]
        let bytes3 = [UInt8]("a201020304".hexadecimal)
        val4.updateValue(Int64(2), forKey: 1)
        val4.updateValue(Int64(4), forKey: 3)
        XCTAssertNotNil(CBORWriter().putIntKeyMap(val4).getResult())
        
        let result3 = CBORReader(bytes: bytes3).readIntKeyMap()
        XCTAssertEqual(result3!.count, 2)
        XCTAssertEqual(result3![1] as! Int64, Int64(2))
        XCTAssertEqual(result3![3] as! Int64, Int64(4))
    }
    
    func testStartArray() {
        let writer = CBORWriter().startArray()
        XCTAssertNotNil(writer)
    }
    
    func testStartMap() {
        let writer = CBORWriter().startMap()
        XCTAssertNotNil(writer)
    }
    
    func testEnd() {
        let writer = CBORWriter().end()
        XCTAssertNotNil(writer)
    }
    
    // MARK: Assert functions
    
    func assertFloat(_ num: Float, _ hex: String) {
        let writer = CBORWriter().putFloat(num).getResult()
        let bytes = [UInt8](hex.hexadecimal)
        XCTAssertEqual(writer, bytes)
        
        let reader = CBORReader(bytes: [UInt8](hex.hexadecimal))
        XCTAssertEqual(reader.readFloat()!, num)
    }
    
    func assertDouble(_ num: Double, _ hex: String) {
        let writer = CBORWriter().putDouble(num).getResult()
        let bytes = [UInt8](hex.hexadecimal)
        XCTAssertEqual(writer, bytes)
        
        let reader = CBORReader(bytes: [UInt8](hex.hexadecimal))
        XCTAssertEqual(reader.readDouble()!, num)
    }
   
    func assertString(_ val: String, _ hex: String) {
        let writer = CBORWriter().putString(val).getResult()
        let bytes = [UInt8](hex.hexadecimal)
        XCTAssertEqual(writer, bytes)
        
        let reader = CBORReader(bytes: [UInt8](hex.hexadecimal))
        XCTAssertEqual(reader.readString()!, val)
    }
    
    func assertByteString(_ val: [UInt8], _ hex: String) {
        let writer = CBORWriter().putByteString(val).getResult()
        let bytes = [UInt8](hex.hexadecimal)
        XCTAssertEqual(writer, bytes)
        
        let reader = CBORReader(bytes: [UInt8](hex.hexadecimal))
        XCTAssertEqual(reader.readByteString()!, val)
    }
    
    func assertBool(_ val: Bool, _ hex: String) {
        let writer = CBORWriter().putBool(val).getResult()
        let bytes = [UInt8](hex.hexadecimal)
        XCTAssertEqual(writer, bytes)
        
        let reader = CBORReader(bytes: [UInt8](hex.hexadecimal))
        XCTAssertEqual(reader.readBool()!, val)
    }
    
    func assertNumber(_ num: Int64, _ hex: String) {
        let writer = CBORWriter().putNumber(num).getResult()
        let bytes = [UInt8](hex.hexadecimal)
        XCTAssertEqual(writer, bytes)
        
        let reader = CBORReader(bytes: [UInt8](hex.hexadecimal))
        XCTAssertEqual(reader.readNumber()!, num)
    }
}
