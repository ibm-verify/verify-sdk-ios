//
// Copyright contributors to the IBM Verify Adaptive SDK for iOS project
//

import UIKit
import os.log

/// The context by while policy driven authentication is managed
final public class AdaptiveContext {
    /// The shared instance of the adaptive context.
    public static let shared = AdaptiveContext()
    
    /// Internal queue for thread safety.
    private let internalQueue = DispatchQueue(label: "AdaptiveContextInternalQueue",  attributes: .concurrent)

    /// An instance of `AdaptiveCollection` implementation
    private var _collectionService: AdaptiveCollectionService?
    
    /// An instance of `AdaptiveCollectionService` implementation
    public var collectionService: AdaptiveCollectionService? {
        get {
            return internalQueue.sync {
                self._collectionService
            }
        }
        set(newState) {
            internalQueue.async(flags: .barrier) {
                self._collectionService = newState
            }
        }
    }
    
    /// Initializes a new instalnce of `AdaptiveContext`.
    private init() {
        os_log("init - entry", log: .default, type: .info)
        removeSessionData()
        
        defer {
            os_log("init - exit", log: .default, type: .info)
        }
        
        /// Subscribe to OS notifications when the hosting application terminates.
        NotificationCenter.default.addObserver(self, selector: #selector(applicationWillTerminate(notification:)), name: UIApplication.willTerminateNotification, object: nil)
        
        /// Subscribe to OS notifications when the hosting application is returned to the foreground.
        NotificationCenter.default.addObserver(self, selector: #selector(applicationWillEnterForeground(notification:)), name: UIApplication.willEnterForegroundNotification, object: nil)
    }
    
    /// The interval in seconds to renew the session identifier. Default is 3,600 (1 hour).
    /// - Remark: This will occur when the application is brought from the background.
    @UserDefault(key: Constants.RenewSessionIdInterval, value: 3600)
    public var renewSessionIdInterval: Int

    /// The session identifier for the hosting application.
    @UserDefault(key: Constants.SessionId, value: UUID().uuidString)
    public var sessionId: String
    
    /// The timestamp of when the session ID was generated or renewed.
    /// - Remark: This will occur when the application is brought from the background.
    @UserDefault(key: Constants.RenewSessionIdTimestamp, value: Date())
    private var renewSessionIdTimestamp: Date
    
    /// Removes the session identifier and session renewal timestamp.
    internal func removeSessionData() {
        os_log("\tcleaning up past stored session information.", log: .default, type: .info)
        
        UserDefaults.standard.removeObject(forKey: Constants.SessionId)
        UserDefaults.standard.removeObject(forKey: Constants.RenewSessionIdTimestamp)
    }
    
    // MARK: Implementation SDK Functions
    
    /// Starts the collection operation on the service implementation.
    /// - Remark: This operation associates the `sessionId` with adaptive authenticaton.
    public func start() throws {
        os_log("start - entry", log: .default, type: .info)
        
        defer {
            os_log("start - exit", log: .default, type: .info)
        }
        
        guard let service = collectionService else {
            os_log("%s", log: .default, type: .info, Constants.UnassignedCollectionService)
            return
        }
        
        do {
            try service.start(with: self.sessionId)
        }
        catch let error {
            throw error
        }
    }
    
    /// Stops the collection operation.
    public func stop() throws {
        os_log("stop - entry", log: .default, type: .info)
        
        defer {
            os_log("stop - exit", log: .default, type: .info)
        }
        
        guard let service = collectionService else {
            os_log("%s", log: .default, type: .info, Constants.UnassignedCollectionService)
            return
        }
        
        do {
            try service.stop()
        }
        catch let error {
            throw error
        }
    }
    
    /// Resets the `sessionId` for collection operation.
    public func reset() throws {
        os_log("reset - entry", log: .default, type: .info)
        
        defer {
            os_log("reset - exit", log: .default, type: .info)
        }
        
        guard let service = collectionService else {
            os_log("%s", log: .default, type: .info, Constants.UnassignedCollectionService)
            return
        }
        
        do {
            sessionId = UUID().uuidString
            UserDefaults.standard.set(sessionId, forKey: Constants.SessionId)
            try service.reset(new: sessionId)
        }
        catch let error {
            throw error
        }
    }
}

extension AdaptiveContext {
    /// Handles the `UIApplication.willTerminateNotification` notification.
    /// - Parameter notification: Posted when the app is about to terminate.
    @objc internal func applicationWillTerminate(notification: Notification) {
        os_log("applicationWillTerminate - entry", log: .default, type: .info)
        
        /// Invoke the collection service to stop provisioning device metadata.
        do {
            defer {
                os_log("applicationWillTerminate - exit", log: .default, type: .info)
            }
            try stop()
            self.removeSessionData()
        }
        catch let error {
            os_log("Error %s", log: .default, type: .error, error.localizedDescription)
        }
    }
    
    /// Handles the `UIApplication.willEnterForegroundNotification` notification.
    /// - Parameter notification: Posted when the app is about to enter the foreground.
    @objc internal func applicationWillEnterForeground(notification: Notification) {
        // Check is the session timestamp plus the renew session interval is less than the current time.  If so, create a new sessionId
        if Date(timeInterval: TimeInterval(renewSessionIdInterval), since: renewSessionIdTimestamp) < Date() {
            os_log("applicationWillEnterForeground - entry", log: .default, type: .info)
            
            defer {
                os_log("applicationWillEnterForeground - exit", log: .default, type: .info)
            }
            
            let oldSessionId = self.sessionId
            self.sessionId = UUID.init().uuidString
            self.renewSessionIdTimestamp = Date()
            
            print("\tcreating a new session identifer.\n\told: \(oldSessionId)\n\tnew: \(self.sessionId)\n\texpires: \(Date(timeInterval: TimeInterval(renewSessionIdInterval), since: Date()))")
            
            // Invoke the collection service to reset the sessionId if assigned.
            guard let service = collectionService else {
                os_log("%s", log: .default, type: .info, Constants.UnassignedCollectionService)
                return
            }
            
            do {
                try service.reset(new: self.sessionId)
            }
            catch let error {
                os_log("Error %s", log: .default, type: .error, error.localizedDescription)
            }
        }
    }
}

/// The **AdaptiveCollectionService** is implemented by risk vendors to commence the collection of mobile device data.
///
/// - Remark: If the context policy doesn't include the A2 mobile risk, `AdaptiveContext` operations **start**, **stop** and **reset** can be ignored.
///
/// ```
/// public struct RiskCollection: AdaptiveCollectionService {
///    public func start(sessionId: String) throws -> Void {
///       // the service operation to start collecting device data.
///    }
///
///    public func stop() throws -> Void {
///       // the service operation to start collecting device data.
///    }
///    public func reset(sessionId: String) throws -> Void {
///       // the service operation to reset collecting device data.
///    }
/// }
///
/// // Assign the risk collection to the field.
/// AdaptiveContext.shared.collectionService = RiskCollection()
///
/// // Start collecting.  Access the unique collection session identifier via AdaptiveContext.shared.sessionId
/// AdaptiveContext.shared.start()
/// ```
public protocol AdaptiveCollectionService {
    /// Starts the collection operation.
    /// - Parameter sessionId: The session identifier for the hosting application.
    /// - Remark: This operation associates the `sessionId` with adaptive authenticaton.
    func start(with sessionId: String) throws
    
    /// Stops the collection operation.
    func stop() throws
    
    /// Resets a collection operation.
    /// - Parameter sessionId: The session identifier for the hosting application.
    func reset(new sessionId: String) throws
}
