//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import Foundation
import FIDO2
import os.log

public class FidoService {
    /// Returns the shared defaults object.
    internal static let shared = FidoService()
    
    // MARK: Networking functions

    func fetchAttestationOptions(_ relyingPartyURL: String, accessToken: String, params: [String: Any]? = [:], completion: @escaping (Result<PublicKeyCredentialCreationOptions, NetworkError>) -> Void) {
        guard let url = URL(string: relyingPartyURL) else {
            completion(.failure(.badURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        
        var parameters = ["attestation":"direct"] as [String: Any]
        
        
        // Append the additional params to the JSON request.
        if let params = params {
            parameters.merge(params) { (current, _) in current }
        }
        
        guard let bodyData = try? JSONSerialization.data(withJSONObject: parameters, options: []) else {
            Logger.networking.debug("Unable to create request payload for WebAuthn.Attestation.options.")
            completion(.failure(NetworkError.invalidData))
            return
        }
            
        Logger.networking.info("HTTP request\n\(String(data: bodyData, encoding: .utf8)!, privacy: .public)")
        request.httpBody = bodyData
        
        URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, let _ = response, error == nil else {
                completion(.failure(.general(message: error!.localizedDescription)))
                return
            }
            
            Logger.networking.info("HTTP response\n\(String(data: data, encoding: .utf8)!, privacy: .public)")
            
            do {
                guard let value = try? JSONDecoder().decode(PublicKeyCredentialCreationOptions.self, from: data) else {
                    Logger.networking.debug("Unable to parse PublicKeyCredentialCreationOptions.")
                    completion(.failure(.general(message: "Unable to parse PublicKeyCredentialCreationOptions.")
                    ))
                    return
                }
                completion(.success(value))
            }
        }.resume()
    }

    func createAuthenticator(_ relyingPartyURL: String, accessToken: String, server: String = isv, nickname: String, enabled: Bool = true, attestation: PublicKeyCredential<AuthenticatorAttestationResponse>, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let url = URL(string: relyingPartyURL) else {
            completion(.failure(NetworkError.badURL))
            return
        }
        
        // Convert into the data the FIDO server wants.
        let data: Data!
        if server == isv {
            let attestation = ISVAttestationResponse(nickname, attestation: attestation)
            data = try? JSONEncoder().encode(attestation)
        }
        else {
            let attestation = ISVAAttestationResponse(nickname, attestation: attestation)
            data = try? JSONEncoder().encode(attestation)
        }
        
        guard let bodyData = data else {
           Logger.networking.debug("Unable to create request payload for WebAuthn.Attestation.create.")
           completion(.failure(NetworkError.invalidData))
           return
       }
       
       var request = URLRequest(url: url)
       request.httpMethod = "POST"
       request.setValue("application/json", forHTTPHeaderField: "Content-type")
       request.setValue("application/json", forHTTPHeaderField: "Accept")
       request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
       request.httpBody = bodyData
       
       Logger.networking.info("HTTP request\n\(String(data: bodyData, encoding: .utf8)!, privacy: .public)")
       
       URLSession.shared.dataTask(with: request) { (data, response, error) in
           guard let data = data, let _ = response, error == nil else {
               completion(.failure(NetworkError.general(message: error!.localizedDescription)))
               return
           }
           
           Logger.networking.info("HTTP response\n\(String(data: data, encoding: .utf8)!, privacy: .public)")
           // Check the response status code that isn't in the 200 range.
           if let httpResponse = response as? HTTPURLResponse, !acceptableStatusCodes.contains(httpResponse.statusCode) {
               // Attempt to read the response error data.
               completion(.failure(NetworkError.general(message: String(data: data, encoding: .utf8) ?? "Invalid")))
               return
           }

           completion(.success(()))
       }.resume()
    }

    func fetchAssertionOptions(_ relyingPartyURL: String, accessToken: String, params: [String: Any]? = [:], completion: @escaping (Result<PublicKeyCredentialRequestOptions, NetworkError>) -> Void) {
        guard let url = URL(string: relyingPartyURL) else {
            completion(.failure(.badURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        
        var parameters = ["userVerification":"required"] as [String: Any]
        
        // Append the additional params to the JSON request.
        if let params = params {
            parameters.merge(params) { (current, _) in current }
        }
        
        guard let bodyData = try? JSONSerialization.data(withJSONObject: parameters, options: []) else {
            Logger.networking.debug("Unable to create request payload for WebAuthn.Assertion.options.")
            completion(.failure(NetworkError.invalidData))
            return
        }
            
        Logger.networking.info("HTTP request\n\(String(data: bodyData, encoding: .utf8)!, privacy: .public)")
        request.httpBody = bodyData
        
        URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, let _ = response, error == nil else {
                completion(.failure(.general(message: error!.localizedDescription)))
                return
            }
            
            Logger.networking.info("HTTP response\n\(String(data: data, encoding: .utf8)!, privacy: .public)")
            
            do {
                guard let value = try? JSONDecoder().decode(PublicKeyCredentialRequestOptions.self, from: data) else {
                    Logger.networking.debug("Unable to parse PublicKeyCredentialRequestOptions.")
                    completion(.failure(.general(message: "Unable to parse PublicKeyCredentialRequestOptions.")
                    ))
                    return
                }
                
                completion(.success(value))
            }
        }.resume()
    }

    func assertAuthenticator<T>(_ relyingPartyURL: String, accessToken: String, username: String, assertion: PublicKeyCredential<AuthenticatorAssertionResponse>, type: T.Type, completion: @escaping (Result<T, Error>) -> Void) where T : AssertionResponse {
        guard let url = URL(string: relyingPartyURL) else {
            completion(.failure(NetworkError.badURL))
            return
        }
            
        guard let bodyData = try? JSONEncoder().encode(assertion) else {
           Logger.networking.debug("Unable to create request payload for WebAuthn.Assertion.get.")
           completion(.failure(NetworkError.invalidData))
           return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.httpBody = bodyData
        
        Logger.networking.info("HTTP request\n\(String(data: bodyData, encoding: .utf8)!,privacy: .public)")
        
        URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let data = data, let _ = response, error == nil else {
                completion(.failure(NetworkError.general(message: error!.localizedDescription)))
                return
            }
            
            Logger.networking.info("HTTP response\n\(String(data: data, encoding: .utf8)!, privacy: .public)")
            
            // Check the response status code that isn't in the 200 range.
            if let httpResponse = response as? HTTPURLResponse, !acceptableStatusCodes.contains(httpResponse.statusCode) {
                // Attempt to read the response error data.
                completion(.failure(NetworkError.general(message: String(data: data, encoding: .utf8) ?? "Invalid")))
                return
            }

            // Parse the response being returned
            guard let result = try? JSONDecoder().decode(T.self, from: data) else {
                completion(.failure(NetworkError.invalidData))
                return
            }
            
            completion(.success(result))
        }.resume()
    }
}
