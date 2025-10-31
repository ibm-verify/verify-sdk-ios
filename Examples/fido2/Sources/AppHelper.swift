//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import UIKit
import os.log
import LocalAuthentication
import FIDO2

// MARK: Constants
let bundleIdentifier = Bundle.main.bundleIdentifier!

// MARK: Enums
enum Store: String {
    case relyingPartyUrl
    case nickname
    case displayName
    case username
    case accessToken
    case createdDate
    case created
    case server
}

enum NetworkError: Error, LocalizedError {
    /// Invalid or format of URL is incorrect.
    case badURL
    
    /// Invalid or no data returned from the serve
    case invalidData
    
    /// General error with custom message.
    case general(message: String)
    
    public var errorDescription: String? {
       switch self {
       case .badURL:
           return NSLocalizedString("Invalid or format of URL is incorrect.", comment: "Invalid URL")
       case .invalidData:
           return NSLocalizedString("Invalid or no data returned from the server.", comment: "Invalid Data")
       case .general(message: let message):
           return NSLocalizedString(message, comment: "General Error")
       }
   }
}

// MARK: Constants
let isva = "isva"
let isv = "isv"


// MARK: Functions

/// HTTP response status codes that are acceptable.
var acceptableStatusCodes: [Int] {
    return Array(200 ..< 300)
}

func createBottomBorder(width: CGFloat, height: CGFloat, color: UIColor = .systemGray3) -> CALayer {
    let layer = CALayer()
    layer.frame = CGRect(x: 0.0, y: height - 1, width: width, height: 1.0)
    layer.backgroundColor = color.cgColor
    return layer
}

// MARK: Extensions
extension Data {
    /// Returns a Base-64 URL encoded string.
    /// - remark: Base-64 URL encoded string removes instances of `=`  and replaces `+` with `-` and `/` with `_`.
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension UIViewController: UITextFieldDelegate {
    /// Asks the delegate whether to process the pressing of the Return button for the text field.
    /// - parameter textField: The text field whose return button was pressed.
    public func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        return textField.resignFirstResponder()
    }
}

extension UIButton {
    /// Sets an `UIActivityIndicatorView` to the button
    /// - parameter show: The flag to show or hide the activity indicator.
    /// - remark: This operation executes on the UI thread.
    func setActivity(_ show: Bool) {
        DispatchQueue.main.async {
            let tag = 808404
            
            if show {
                self.isEnabled = false
                
                let buttonHeight = self.bounds.size.height
                let buttonWidth = self.bounds.size.width
                
                let activity = UIActivityIndicatorView()
                activity.color = .white
                activity.style = .medium
                activity.center = CGPoint(x: buttonWidth - activity.frame.width - 30, y: buttonHeight / 2)
                activity.tag = tag
                
                self.addSubview(activity)
                activity.startAnimating()
            }
            else {
                self.isEnabled = true
                
                if let activity = self.viewWithTag(tag) as? UIActivityIndicatorView {
                    activity.stopAnimating()
                    activity.removeFromSuperview()
                }
            }
        }
    }
}

extension UIView {
    func setCornerRadius(_ cornerRadius: CGFloat = 8) {
        self.layer.cornerRadius = cornerRadius
    }
    
    func setBorderBottom(color: UIColor = .systemGray3, lineHeight: CGFloat = 1) {
        let layer = CALayer()
        layer.frame = CGRect(x: 0, y: self.frame.height - lineHeight, width: UIScreen.main.bounds.width, height: lineHeight)
        layer.backgroundColor = color.cgColor

        self.layer.addSublayer(layer)
        self.layer.masksToBounds = true
    }
}

extension Logger {
    private static var subsystem = Bundle.main.bundleIdentifier!

    /// Logs app related messages.
    static let app = Logger(subsystem: subsystem, category: "app")
    
    /// Logs networking operations.
    static let networking = Logger(subsystem: subsystem, category: "networking")
}
