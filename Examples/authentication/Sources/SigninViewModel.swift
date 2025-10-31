//
// Copyright contributors to the IBM Verify Authentication Sample App for iOS project
//

import Foundation
import Authentication
import AuthenticationServices

class SignInViewModel: NSObject, ObservableObject {
    @Published var token: TokenInfo?
    var codeVerifier: String? = nil
    var codeChallenge: String? = nil
    var tokenURL: URL?
    var redirectURL: URL?
    
    // TODO: Update this value if your tenant application is configured as a non-public client.
    let clientSecret = ""
    
    func performSignin(_ authorizationUrl: String, tokenUrl: String, redriectUrl: String, clientId: String, usePKCE: Bool, shareSession: Bool, includeState: Bool) {
        // Create the code verifier for PKCE
        if usePKCE {
            self.codeVerifier = PKCE.generateCodeVerifier()
            self.codeChallenge = PKCE.generateCodeChallenge(from: self.codeVerifier!)
        }
        
        // OAuth configuration
        let issuerURL = URL(string: authorizationUrl)!
        self.redirectURL = URL(string: redriectUrl)!
        self.tokenURL = URL(string: tokenUrl)!
        
        let provider = OAuthProvider(clientId: clientId, clientSecret: self.clientSecret)
        provider.delegate = self
        
        provider.authorizeWithBrowser(issuer: issuerURL,
                                      redirectUrl: self.redirectURL!,
                                      presentingViewController: self,
                                      codeChallenge: codeChallenge,
                                      method: .S256,
                                      state: includeState ? UUID().uuidString : nil,
                                      shareSession: shareSession)
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding
extension SignInViewModel: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
}

// MARK: - OAuthProviderDelegate
extension SignInViewModel: OAuthProviderDelegate {
    func oauthProvider(provider: OAuthProvider, didCompleteWithError error: Error) {
        print(error.localizedDescription)
    }
    
    @MainActor
    func oauthProvider(provider: OAuthProvider, didCompleteWithCode result: (code: String, state: String?))  {
        Task {
            do {
                let result = try await provider.authorize(issuer: tokenURL!, redirectUrl: self.redirectURL, authorizationCode: result.code, codeVerifier: self.codeVerifier)
                self.token = result
            }
            catch let error {
                print("error \(error.localizedDescription)")
            }
        }
    }
}
