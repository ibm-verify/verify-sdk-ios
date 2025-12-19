//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import Foundation
import Core
import MFA

class DataManager {
    private let fileManager: FileManager = FileManager.default
    private let fileName = "authenticator.json"
    private var fileLocation: URL {
        let url = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!
        return url.appendingPathComponent(fileName)
    }

    init() {
        print(fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!)
    }
    
    // Load the authenticator from UserDefaults.
    func load() -> (any MFAAuthenticatorDescriptor)? {
        if let data = try? Data(contentsOf: fileLocation) {
            if let authenticator = try? JSONDecoder().decode(CloudAuthenticator.self, from: data) {
                return authenticator
            }
            
            if let authenticator = try? JSONDecoder().decode(OnPremiseAuthenticator.self, from: data) {
                return authenticator
            }
        }
        
        return nil
    }
    
    func exists() -> Bool {
        return fileManager.fileExists(atPath: fileLocation.path)
    }
    
    func save(authenticator: any MFAAuthenticatorDescriptor) throws {
        do {
            let data = try JSONEncoder().encode(authenticator)
            try data.write(to: fileLocation)
        }
        catch let error {
            throw error
        }
    }
    
    func reset() throws {
        do {
            try fileManager.removeItem(at: fileLocation)
        }
        catch let error {
            throw error
        }
    }
}

extension DataManager {
    static func saveBiometricPrivateKey(_ key: SecKeyAddType) throws -> String {
        // Generate a unique label for the key
        let keyLabel = "\(UUID().uuidString).privateKey"
    
        try KeychainService.default.addItem(keyLabel, value: key, accessControl: .userPresence)
        
        return keyLabel
    }
}
