//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

extension NSNumber {
    /// A Boolean value that indicates whether the instance is a Boolean value.
    public var isBool: Bool {
        return CFBooleanGetTypeID() == CFGetTypeID(self)
    }
}
