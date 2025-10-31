//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import Foundation
import os.log

// MARK: Structures

/// Represents the ivcreds from the Web Reverse Proxy.
public struct IVCreds {
    /// Represents the username - extracted from AZN_CRED_PRINCIPAL_NAME attribute
    public var username: String
    
    /// Represents all other attributes of the cred
    public var attributes: [String: Any]?
    
    enum IVCredsError: Error {
        case notAuthenticated
    }
    
    // Creates a new `IVCreds` instance
    public init(jsonData: Data) throws {
        self.username = "unauthenticated"
        let json = try? JSONSerialization.jsonObject(with: jsonData, options: [])
        if let ivcreds = json as? [String:Any] {
            if ivcreds["AZN_CRED_PRINCIPAL_NAME"] == nil || ivcreds["AZN_CRED_PRINCIPAL_NAME"] as! String == "unauthenticated"  {
                throw IVCredsError.notAuthenticated
            }
            self.username = ivcreds["AZN_CRED_PRINCIPAL_NAME"] as! String
            self.attributes = ivcreds
        }
    }
}

extension IVCreds {
    /// Constructs a IVCreds URL from a string.
    static func buildURL(_ serverURL: String) -> String {
        let url = URL(string: serverURL)!

        var ivCreds = url.scheme! + "://" + url.host!
        if (url.port != nil) {
            ivCreds += ":" + String(url.port!)
        }
        ivCreds += "/ivcreds"
        return ivCreds
    }
    
    static func  getWhoAmI(_ whoAmIURL: String, accessToken: String, completion: @escaping (Result<IVCreds, NetworkError>) -> Void) {
        guard let url = URL(string: whoAmIURL) else {
            completion(.failure(.badURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        let logstr = "curl -H \"Accept: application/json\" -H \"Authorization: Bearer " + accessToken + " " + whoAmIURL
        Logger.networking.info("HTTP request\n\(logstr, privacy: .public)")
                    
        URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, let _ = response, error == nil else {
                completion(.failure(.general(message: error!.localizedDescription)))
                return
            }
            
            Logger.networking.info("HTTP response\n\(String(data: data, encoding: .utf8)!, privacy: .public)")
            do {
                guard let value = try? IVCreds(jsonData: data) else {
                    completion(.failure(.general(message: "\(String(data: data, encoding: .utf8) ?? "Invalid")")
                    ))
                    return
                }
                completion(.success(value))
            }
        }.resume()
    }
}
