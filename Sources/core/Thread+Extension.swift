//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation

extension Thread {
    /// The identifier of the receiver (often called thread ID).
    /// - note: Returns the number from `Thread.current.description` representing the thread identifier.  Where no match is found `-1` is returned.
    public var threadIdentifier: Int32 {
        get {
            let regex = try! NSRegularExpression(pattern: "num(?:ber)?[^0-9]+([0-9]+)", options: .caseInsensitive)
           
            // Perform the match.
            guard let match = regex.firstMatch(in: description, options: [], range: NSRange(location: 0, length: description.utf16.count)) else {
                return -1
            }
                
            // Extract the group from the match.
            guard let number = Range(match.range(at: 1), in: description), let result = Int32(description[number]) else {
                  return -1
            }

            return result
        }
    }
}
