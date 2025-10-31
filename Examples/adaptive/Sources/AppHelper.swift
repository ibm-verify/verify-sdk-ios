//
// Copyright contributors to the IBM Verify Adaptive Sample App for iOS project
//

import Foundation
import UIKit
import Adaptive

// MARK: Constants

/// The URL to the IBM Verify tenant. This URL below is an example tenant.  Or if you are running the NodeJS Porxy SDK, use an IP address.
let baseUrl = "https://craig.casey.com.au" // "https://proxy-sdk.au-syd.mybluemix.net" // Proxy SDK update the IP address

// MARK: Properties

// Gets or sets the flag to indicate if a FIDO platform authenticator has been registered.
var isFIDORegistered: Bool {
    get {
        let value = UserDefaults.standard.value(forKey: "isFIDORegistered") as? Bool ?? false
        print("isFIDORegistered: \(value)")
        return value
    }
    set {
        UserDefaults.standard.setValue(newValue, forKey: "isFIDORegistered")
    }
}

/// Gets the `access_token` value from the persisteted token data.
/// - remarks: Returns `nil` is token data is not found or an error occured in parsing the token JSON.
var accessToken: String? {
    guard let token = retrieveToken() else {
        return nil
    }
    
    guard let data = token.data(using: .utf8) else {
        return nil
    }
    
    do {
        guard let result = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            return nil
        }
        
        if let value = result["access_token"] as? String {
            print(value)
            
            return value
        }
    }
    catch {
        print(error.localizedDescription)
    }
    
    return nil
}

/// Gets the `id_token` value from the persisteted token data.
/// - remarks: Returns `nil` is token data is not found or an error occured in parsing the token JSON.
var idToken: [String: Any]? {
    guard let token = retrieveToken() else {
        return nil
    }
    
    guard let data = token.data(using: .utf8) else {
        return nil
    }
    
    do {
        guard let result = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            return nil
        }
        
        // Get the id_token from the payload
        if let value = result["id_token"] as? String {
            // Get the payload segment of the id_tokeb
            let segments = value.components(separatedBy: ".")[1]
             
            // Convert the id_token from base64
            var base64 = segments
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            if base64.count % 4 > 0 {
                base64.append(String(repeating: "=", count: 4 - base64.count % 4))
            }
            
            // Convert the base64 data (JSON) into a dictionary
            guard let data = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
                return nil
            }
            
            guard let result = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                return nil
            }
           
            return result
        }
    }
    catch {
        print(error.localizedDescription)
    }
    
    return nil
}


// MARK: Functions
func createButton(_ title: String) -> UIButton {
    let button = UIButton(type: .custom)
    button.setTitleColor(.systemBackground, for: .normal)
    button.setTitle(title, for: .normal)
    button.titleLabel?.font =  .systemFont(ofSize: 17, weight: .semibold)
    button.layer.cornerRadius = 5
    button.backgroundColor = .systemBlue
    button.translatesAutoresizingMaskIntoConstraints = false
    button.heightAnchor.constraint(equalToConstant: 64).isActive = true
   
    return button
}

func createBottomBorder(width: CGFloat, height: CGFloat, color: UIColor = .systemGray3) -> CALayer {
    let layer = CALayer()
    layer.frame = CGRect(x: 0.0, y: height - 1, width: width, height: 1.0)
    layer.backgroundColor = color.cgColor
    return layer
}

func saveToken(_ token: String) {
    UserDefaults.standard.setValue(token, forKey: "token")
}

func retrieveToken() -> String? {
    guard let token = UserDefaults.standard.value(forKey: "token") as? String else {
        return nil
    }
    return token
}

/// Parses the response from a FIDO login operation.
/// - remarks: If the JSON can not be parsed, then `DenyAssessmentResult` is return.
func parseFIDOResponse(_ json: String) -> AdaptiveResult {
    guard let data = json.data(using: .utf8) else {
        return DenyAssessmentResult()
    }
    
    do {
        guard let result = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            return DenyAssessmentResult()
        }
        
       if let value = result["status"] as? String, value == "allow", let token = result["token"] as? [String: Any] {
            // Convert the token back to JSON
            if let jsonData = try? JSONSerialization.data(withJSONObject: token, options: []) {
                if let jsonString = String(data: jsonData, encoding: .utf8) {
                    return AllowAssessmentResult(jsonString)
                }
            }
        }
    }
    catch {
        print(error.localizedDescription)
    }
    
    return DenyAssessmentResult()
}


// MARK: Structures

// The AnyDecodable structure enables JSON decoding of different undeclared data types.
public struct AnyDecodable: Decodable {
    public var value: Any

    private struct CodingKeys: CodingKey {
        var stringValue: String
        var intValue: Int?
    
        init?(intValue: Int) {
            self.stringValue = "\(intValue)"
            self.intValue = intValue
        }
    
        init?(stringValue: String) {
            self.stringValue = stringValue
        }
    }

    public init(from decoder: Decoder) throws {
        if let container = try? decoder.container(keyedBy: CodingKeys.self) {
            var result = [String: Any]()
            try container.allKeys.forEach { key throws in
                result[key.stringValue] = try container.decode(AnyDecodable.self, forKey: key).value
            }
            value = result
        }
        else if var container = try? decoder.unkeyedContainer() {
            var result = [Any]()
            while !container.isAtEnd {
                result.append(try container.decode(AnyDecodable.self).value)
            }
            value = result
        }
        else if let container = try? decoder.singleValueContainer() {
            if let intVal = try? container.decode(Int.self) {
                value = intVal
            }
            else if let doubleVal = try? container.decode(Double.self) {
                value = doubleVal
            }
            else if let boolVal = try? container.decode(Bool.self) {
                value = boolVal
            }
            else if let stringVal = try? container.decode(String.self) {
                value = stringVal
            }
            else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "The container has no serializable data.")
            }
        }
        else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Unable to serialize data."))
        }
    }
}

// MARK: Extensions

extension UIButton {
    /// Sets an `UIActivityIndicatorView` to the button
    func setActivity(_ show: Bool) {
        let tag = 808404
        
        if show {
            self.isEnabled = false
            
            let buttonHeight = self.bounds.size.height
            let buttonWidth = self.bounds.size.width
            
            let activity = UIActivityIndicatorView()
            activity.color = .systemBackground
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

extension UIControl {
    private static var _customIdentifier: String?
    
    var customIdentifier: String? {
        get {
            return objc_getAssociatedObject(self, &UIControl._customIdentifier) as? String
        }
        set {
            objc_setAssociatedObject(self, &UIControl._customIdentifier, newValue, .OBJC_ASSOCIATION_RETAIN)
        }
    }
}

extension UIViewController: UITextFieldDelegate {
    /// Asks the delegate whether to process the pressing of the Return button for the text field.
    /// - parameter textField: The text field whose return button was pressed.
    public func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        textField.resignFirstResponder()
        return true
    }
}

extension Notification.Name {
    static var safariDismissRegister: Notification.Name {
          return .init(rawValue: "safari.dismiss.registration")
    }
    
    static var safariDismissLogin: Notification.Name {
          return .init(rawValue: "safari.dismiss.login")
    }
}
