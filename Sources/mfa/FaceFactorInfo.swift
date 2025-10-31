//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

/// A signature factor refers to the use of a digital signature as a second factor to authenticate an external entity. The fingerprint factor denotes the use of FaceID.
public struct FaceFactorInfo: Factor {
    public let id: UUID
    
    public let displayName = "Face ID"
    
    /// The name to identify the Keychain item associated with the factor.
    public let name: String
    
    /// The algorithm used to calculate a hash for data signing.
    public let algorithm: HashAlgorithmType
    
    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case algorithm
    }
}
