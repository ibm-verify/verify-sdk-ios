//
// Copyright contributors to the IBM Verify Authentication Sample App for iOS project
//

import SwiftUI

struct ContentView: View {
    @StateObject var viewModel = SignInViewModel()
    @State private var authorizationURL: String = "https://sdk.verify.ibm.com/v1.0/endpoint/default/authorize"
    @State private var tokenURL: String = "https://sdk.verify.ibm.com/v1.0/endpoint/default/token"
    @State private var clientId: String = "38cdeff8-9693-4f0b-99c9-563d5c20d6a7"
    @State private var redirectURL: String = "verifysdk://auth/callback"
    @State private var usePKCE: Bool = true
    @State private var shareSession: Bool = true
    @State private var includeState: Bool = false
    
    var body: some View {
        NavigationView {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "person.circle")
                .resizable()
                .frame(width: 50, height: 50)
                .foregroundColor(.blue)
            
                VStack(spacing: 8) {
                    Text("This sample app demonstrates initiating an OAuth2 authorization code flow and exchanging it for an access token.")
                        .foregroundColor(.secondary)
                        .font(.title2)
                        .multilineTextAlignment(.center)
                        .padding()
                    
                    ScrollViewReader {_ in
                        Form {
                            Section(header: Text("Authorization Endpoint")) {
                                TextField(text: $authorizationURL, prompt: Text("Authorization URL")) {
                                        Text("The URL to the authorization endpoint.")
                                }
                            }
                            Section(header: Text("Token Endpoint")) {
                                TextField(text: $tokenURL, prompt: Text("Token URL")) {
                                        Text("The URL to the token endpoint.")
                                }
                            }
                            Section(header: Text("Redirect Callback")) {
                                TextField(text: $redirectURL, prompt: Text("Redirect URL")) {
                                        Text("The URL to the redirect scheme.")
                                }
                            }
                            Section(header: Text("Client ID")) {
                                TextField(text: $clientId, prompt: Text("Client ID")) {
                                        Text("The client identifier.")
                                }
                            }
                            Section(header: Text("Configuration Options")) {
                                Toggle("Use PKCE", isOn: $usePKCE)
                                Toggle("Share session", isOn: $shareSession)
                                Toggle("Include state", isOn: $includeState)
                            }
                        }.padding()
                        .cornerRadius(16)
                    }
                    
                    HStack {
                        Button {
                            viewModel.performSignin(authorizationURL, tokenUrl: tokenURL, redriectUrl: redirectURL, clientId: clientId, usePKCE: usePKCE,
                                shareSession: shareSession, includeState: includeState
                            )
                        } label: {
                            Text("Get started")
                                .frame(maxWidth:.infinity)
                                .foregroundColor(.white)
                                .padding()
                                .background(.blue)
                                .cornerRadius(8)
                        }
                        
                        
                    }.frame(maxWidth:.infinity)
                    .padding(16)
                    
                    NavigationLink(destination: TokenView()) {
                        Text("Display token")
                    }
                }
            }
        }.environmentObject(viewModel)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
