//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import XCTest
@testable import MFA

class PendingTransactionInfoTest: XCTestCase {
    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }
    
    func testPendingTransactionInit() throws {
        // Given
        let value = PendingTransactionInfo(id: "abcd-efgh-ijkl", message: "Some transaction", postbackUri: URL(string: "https://sdk.verify.ibm.com")!, keyName: UUID().uuidString, factorId: UUID().uuidString, factorType: "userPresence", dataToSign: "d4e5f6", timeStamp: Date(), additionalData: [TransactionAttribute.ipAddress: "1.1.1.1"])
        
        // When, Then
        XCTAssertNotNil(value, "Pending transaction initialized")
    }
    
    func testPendingTransactionShort() throws {
        // Given
        let value = PendingTransactionInfo(id: "abcd-efgh-ijkl", message: "Some transaction", postbackUri: URL(string: "https://sdk.verify.ibm.com")!, keyName: UUID().uuidString, factorId: UUID().uuidString, factorType: "userPresence", dataToSign: "d4e5f6", timeStamp: Date(), additionalData: [TransactionAttribute.ipAddress: "1.1.1.1"])
        
        // When, Then
        XCTAssertEqual(value.shortId, "abcd")
    }
}
