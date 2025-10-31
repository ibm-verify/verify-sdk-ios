//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import Foundation
@testable import Adaptive

class MockCollectionService: AdaptiveCollectionService {
    // MARK: Initializer
    public init() {
    }
    
    // MARK: AdaptiveCollection SDK Functions
    
    /// Starts the collection operation.
    /// - Parameter sessionId: The session identifier for the hosting application.
    /// - Remark: This operation associates the `sessionId` with adaptive authenticaton.
    public func start(with sessionId: String) throws {
        print("Start collection service with session: \(sessionId)")
    }
    
    /// Stops the collection operation.
    public func stop() throws{
        print("Stop collection service")
    }
    
    /// Resets the collection operation with a new session identifier
    /// - Parameter sessionId: The session identifier for the hosting application.
    public func reset(new sessionId: String) throws {
       print("Reset collection service with session: \(sessionId)")
    }
}
