//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation
import UIKit
import LocalAuthentication
import Core

/// Wrapper around `UIDevice` to extend device attributes for multi-factor registration.
public enum MFAAttributeInfo {
    /// A representation of the current device.
    private static let uiDevice = UIDevice.current
    
    /// A mechanism for evaluating authentication policies and access controls.
    private static let laContext = LAContext()
    
    /// Returns the bundle object that contains the current executable.
    private static let bundle = Bundle.main
    
    // MARK: Device information
    
    /// The name of the device.
    public static var name: String {
        get {
            self.uiDevice.name
        }
    }
    
    /// The model of the device.
    public static var model: String {
        get {
            self.uiDevice.model
        }
    }
    
    /// The name of the operating system running on the device.
    public static var operatingSystem: String {
        get {
            self.uiDevice.systemName
        }
    }
    
    /// The current version of the operating system.
    public static var operatingSystemVersion: String {
        get {
            self.uiDevice.systemVersion
        }
    }
    
    /// The flag to indicate if the device contains known jailbroken technique.
    public static var deviceInsecure: Bool {
        get {
            #if targetEnvironment(simulator)
                return false
            #else
                // Reading and writing in system directories (sandbox violation)
                do {
                    let path = "/private/" + UUID().uuidString
                    try path.write(toFile: path, atomically: true, encoding: .utf8)
                    try FileManager.default.removeItem(atPath: path)
                    return true
                } catch {
                    return false
                }
            #endif
        }
    }
    
    /// An alphanumeric string that uniquely identifies a device to the app’s vendor.
    public static var deviceID: String {
        get {
            // Check the Keychain for the device identifier, if it exists, return it.
            if KeychainService.default.itemExists("deviceId"), let result = try? KeychainService.default.readItem("deviceId", type: String.self) {
                return result
            }
            
            // Write to the Keychain with new UUID.
            let newDeviceID = UUID().uuidString
            
            try? KeychainService.default.addItem("deviceId", value: newDeviceID, accessControl: .none, accessibility: .afterFirstUnlock)
            
            return newDeviceID
        }
    }
    
    // MARK: - Device hardware
    
    /// A value that indicates a capture device is on the front side of an iOS device.
    public static var hasFrontCamera: Bool {
        get {
            return true
        }
    }
    
    /// The device supports Face ID.
    public static var hasFaceID: Bool {
        get {
            laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            return laContext.biometryType == .faceID
        }
    }
    
    /// The device supports Touch ID.
    public static var hasTouchID: Bool {
        get {
            laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            return laContext.biometryType == .touchID
        }
    }
    
    // MARK: - Application information
    
    /// The unique string that identifies the app.
    public static var applicationBundleIdentifier: String {
        get {
            return self.bundle.bundleIdentifier!
        }
    }
    
    /// The human-readable name of the bundle.
    public static var applicationName: String {
        get {
            return self.bundle.infoDictionary?[kCFBundleNameKey as String] as! String
        }
    }

    /// The release or version number of the bundle.
    /// - Remark: The format is returned as `1.0 (3)`.
    public static var applicationVersion: String {
        get {
            let version = self.bundle.infoDictionary?["CFBundleShortVersionString"] as! String
            let build = self.bundle.infoDictionary?[kCFBundleVersionKey as String] as! String
            return "\(version) (\(build))"
        }
    }
    
    /// The release or version number of the framework.
    /// - Remark: This value represents the latest [Github release version](https://github.com/ibm-verify/verify-mobile-ios/releases/tag).
    public static var frameworkVersion: String {
        get {
            return "3.0.5"
        }
    }
    
    /// Returns the attribute info’s as a dictionary.
    /// - Parameters:
    ///   - snakeCaseKey: A flag to transform the dictionary key from camel case to snake case format. Default is `false`.
    ///
    /// - Returns: A dictionary of the property names and values.
    public static func dictionary(snakeCaseKey: Bool = false) -> [String: Any] {
        return [snakeCaseKey ? "applicationId".toSnakeCase() : "applicationId": self.applicationBundleIdentifier,
                snakeCaseKey ? "applicationName".toSnakeCase() : "applicationName": self.applicationName,
                snakeCaseKey ? "applicationVersion".toSnakeCase() : "applicationVersion": self.applicationVersion,
                snakeCaseKey ? "deviceName".toSnakeCase() : "deviceName": self.name,
                snakeCaseKey ? "platformType".toSnakeCase() : "platformType": self.operatingSystem.uppercased(),
                snakeCaseKey ? "deviceType".toSnakeCase() : "deviceType": self.model,
                snakeCaseKey ? "deviceId".toSnakeCase() : "deviceId": self.deviceID,
                snakeCaseKey ? "osVersion".toSnakeCase() : "osVersion": self.operatingSystemVersion,
                snakeCaseKey ? "faceSupport".toSnakeCase() : "faceSupport": self.hasFaceID,
                snakeCaseKey ? "deviceInsecure".toSnakeCase() : "deviceInsecure": self.deviceInsecure,
                snakeCaseKey ? "fingerprintSupport".toSnakeCase() : "fingerprintSupport": self.hasTouchID,
                snakeCaseKey ? "frontCameraSupport".toSnakeCase() : "frontCameraSupport": self.hasFrontCamera,
                snakeCaseKey ? "verifySdkVersion".toSnakeCase() : "verifySdkVersion": self.frameworkVersion
        ]
    }
}
