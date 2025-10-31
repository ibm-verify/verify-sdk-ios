//
// Copyright contributors to the IBM Verify Authentication Sample App for iOS project
//

import SwiftUI
import Authentication

struct TokenView: View {
    @EnvironmentObject var viewModel: SignInViewModel
    
    var body: some View {
        Form {
            Section(header: Text("Access Token")) {
                if let token = viewModel.token {
                    Text(token.accessToken)
                }
                else {
                    Text("No token was generated.")
                }
            }
            Section(header: Text("Refresh Token")) {
                if let token = viewModel.token, let refreshToken = token.refreshToken {
                    Text(refreshToken)
                }
                else {
                    Text("No refresh token was generated.")
                }
            }
            Section(header: Text("Token Type")) {
                if let token = viewModel.token {
                    Text(token.tokenType)
                }
                else {
                    Text("No token type was generated.")
                }
            }
            Section(header: Text("Expires In")) {
                if let token = viewModel.token {
                    Text("\(token.expiresIn)")
                }
                else {
                    Text("No expiry time was generated.")
                }
            }
        }.padding()
            .cornerRadius(16)
        
    }
}

struct TokenView_Previews: PreviewProvider {
    static var previews: some View {
        TokenView()
    }
}
