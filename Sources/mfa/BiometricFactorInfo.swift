//
// Copyright contributors to the IBM Verify MFA SDK for iOS project
//

import Foundation

/// A signature factor refers to the use of a digital signature as a second factor to authenticate an external entity.
public struct BiometricFactorInfo: Factor, Equatable {
    public let id: String
    
    public var displayName = MFAAttributeInfo.biometryName
    
    public var imageName = MFAAttributeInfo.biometryImage
    
    /// The name to identify the Keychain item associated with the factor.
    public let name: String
    
    /// The algorithm used to calculate a hash for data signing.
    public let algorithm: SigningAlgorithm
}
