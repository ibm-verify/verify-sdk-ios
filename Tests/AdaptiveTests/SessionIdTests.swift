//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import XCTest
@testable import Adaptive

class SessionIdTests: XCTestCase {
    /// Put setup code here. This method is called before the invocation of each test method in the class.
    override func setUp() {
    }

    override func tearDown() {
    }
    
    /// This test creates a session identifier and makes sure it's an UUID.
    func testCreateSessionIdAsUUID() {
        let sessionId1 = AdaptiveContext.shared.sessionId
        guard let sessionId2 = UUID.init(uuidString: sessionId1) else {
            XCTFail()
            return
        }

        XCTAssert(sessionId1 == sessionId2.uuidString)
    }

    /// This test creates a session identifier twice and compares to make sure they are the same,
    func testCompareSessionId() {
        let sessionId1 = AdaptiveContext.shared.sessionId
        let sessionId2 = AdaptiveContext.shared.sessionId

        XCTAssert(sessionId1 == sessionId2)
    }
    
    /// Simulates the application entering the foreground, generating a new session identifier.
    /// - remarks: The`renewSessionIdInterval` is set to 1 and the test waits 5 seconds.
    func testAppForegroundNotification() {
        let session1 = AdaptiveContext.shared.sessionId
        
        // Set the renewal interval to 1 second
        AdaptiveContext.shared.renewSessionIdInterval = 1
        sleep(5)
        
        AdaptiveContext.shared.applicationWillEnterForeground(notification: Notification(name:  Notification.Name(rawValue: "willEnterForegroundNotification")))
        
        let session2 = AdaptiveContext.shared.sessionId
        XCTAssert(session1 != session2)
    }
    
    /// Simulates the application being terminated.  Check if the saved sessionId exists.
    func testAppTerminateNotification() {
       // let expectation = XCTestExpectation(description: "willTerminateNotification")
        
        AdaptiveContext.shared.collectionService = MockCollectionService()
        try? AdaptiveContext.shared.start()
        
        func terminateApp(completion: @escaping () -> Void) { AdaptiveContext.shared.applicationWillTerminate(notification: Notification(name:  Notification.Name(rawValue: "willTerminateNotification")))
        }
        
        terminateApp() {
            // expectation.fulfill()
            if let _ = UserDefaults.standard.string(forKey: Constants.SessionId) {
                XCTFail()
            }
            else {
                XCTAssert(true)
            }
        }
    }
    
    /// Test to remove session data from `UserDefaults`.
    func testRemoveSessionData() {
        let session1 = AdaptiveContext.shared.sessionId
        AdaptiveContext.shared.removeSessionData()
        AdaptiveContext.shared.sessionId = UUID().uuidString
        let session2 = AdaptiveContext.shared.sessionId
        
        XCTAssert(session1 != session2)
    }
    
    func testUserDefaultWithString() {
        // Given
        let value = "Hello World"
        
        // When
        var result = UserDefault(key: "string", value: value)
        
        // Then
        XCTAssertEqual(UserDefaults.standard.string(forKey: "string"), value)
        XCTAssertEqual(result.wrappedValue, value)

        // Then
        let newValue = "World Hello"
        result.wrappedValue = newValue
        XCTAssertEqual(UserDefaults.standard.string(forKey: "string"), newValue)
        XCTAssertEqual(result.wrappedValue, newValue)
    }
    
    func testUserDefaultWithInt() {
        // Given
        let value = 0
        
        // When
        var result = UserDefault(key: "integer", value: value)

        // Then
        XCTAssertEqual(UserDefaults.standard.integer(forKey: "integer"), value)
        XCTAssertEqual(result.wrappedValue, value)

        // Then
        let newValue = 1
        result.wrappedValue = newValue
        XCTAssertEqual(UserDefaults.standard.integer(forKey: "integer"), newValue)
        XCTAssertEqual(result.wrappedValue, newValue)
    }
    
    func testUserDefaultWithBool() {
        // Given
        let value = false
        
        // When
        var result = UserDefault(key: "boolean", value: value)

        // Then
        XCTAssertEqual(UserDefaults.standard.bool(forKey: "boolean"), value)
        XCTAssertEqual(result.wrappedValue, value)

        // Then
        let newValue = true
        result.wrappedValue = newValue
        XCTAssertEqual(UserDefaults.standard.bool(forKey: "boolean"), newValue)
        XCTAssertEqual(result.wrappedValue, newValue)
    }
    
    func testUserDefaultWithDouble() {
        // Given
        let value = 9.95
        
        // When
        var result = UserDefault(key: "double", value: value)

        // Then
        XCTAssertEqual(UserDefaults.standard.double(forKey: "double"), value)
        XCTAssertEqual(result.wrappedValue, value)

        // Then
        let newValue = 4.56
        result.wrappedValue = newValue
        XCTAssertEqual(UserDefaults.standard.double(forKey: "double"), newValue)
        XCTAssertEqual(result.wrappedValue, newValue)
    }
    
    func testUserDefaultWithObject() {
        // Given
        let value = Date.distantPast
        
        // When
        var result = UserDefault(key: "date", value: value)

        // Then
        XCTAssertEqual(UserDefaults.standard.object(forKey: "date") as! Date, value)
        XCTAssertEqual(result.wrappedValue, value)

        // Then
        let newValue = Date()
        result.wrappedValue = newValue
        XCTAssertEqual(UserDefaults.standard.object(forKey: "date") as! Date, newValue)
        XCTAssertEqual(result.wrappedValue, newValue)
    }
}
