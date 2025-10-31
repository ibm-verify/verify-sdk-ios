//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import XCTest
@testable import Adaptive

class AdaptiveContextTests: XCTestCase {    
    /// Put setup code here. This method is called before the invocation of each test method in the class.
    override func setUp() {
    }

    override func tearDown() {
        AdaptiveContext.shared.collectionService = mockCollectionService
        try? AdaptiveContext.shared.start()
    }
    
    // MARK: Collection
    /// This test invokes the collection of device information.
    func testStartCollection() {
        do {
            AdaptiveContext.shared.collectionService = mockCollectionService
            try AdaptiveContext.shared.start()
            XCTAssertTrue(true)
        }
        catch(let error) {
            print("Error \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    /// This test stops the collection of device information.
    func testStopCollection() {
        do {
            AdaptiveContext.shared.collectionService = mockCollectionService
            try AdaptiveContext.shared.stop()
            XCTAssertTrue(true)
        }
        catch(let error) {
            print("Error \(error.localizedDescription)")
            XCTFail()
        }
    }
    
    /// This test invokes the collection of device information without assigning the `collectionService`.
    func testStartCollectionFail() {
        do {
            AdaptiveContext.shared.collectionService = nil
            try AdaptiveContext.shared.start()
        }
        catch(let error) {
            print("Error \(error.localizedDescription)")
            XCTAssertTrue(true)
        }
    }
    
    /// This test invokes the collection of device information without assigning the `collectionService`.
    func testStopCollectionFail() {
        do {
            AdaptiveContext.shared.collectionService = nil
            try AdaptiveContext.shared.stop()
        }
        catch(let error) {
            print("Error \(error.localizedDescription)")
            XCTAssertTrue(true)
        }
    }
}
