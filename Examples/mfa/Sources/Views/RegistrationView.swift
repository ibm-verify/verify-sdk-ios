//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import SwiftUI

struct RegistrationView: View {
    @Environment(\.dismiss) var dismiss
    @State var code: String = String()
    @State private var isProcessing = false
    @StateObject private var model: RegistrationViewModel = RegistrationViewModel()
    @FocusState private var isFocused: Bool
    
    var body: some View {
        VStack {
            VStack {
                Text("Registering your account")
                    .font(.title)
                    .padding()
                Text("We'll validate the QR code, then start the account registration.")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.bottom)
            
                VStack {
                    Text("How would you like to identify the account?")
                    TextField("Account nickname", text: $model.accountName)
                        .focused($isFocused)
                        .frame(minHeight: 28)
                        .padding(10)
                        .overlay(RoundedRectangle(cornerRadius: 8)
                            .stroke(Color(.systemGray5), lineWidth: 1))
                        
                }.padding(16)
            }
                
            Spacer()
            
            VStack {
                Button(action: {
                    Task {
                        self.isProcessing.toggle()
                        await model.validateCode(code: code)
                        self.isProcessing.toggle()
                    }
                }) {
                    ZStack {
                        Image("busy")
                            .rotationEffect(.degrees(self.isProcessing ? 360.0 : 0.0))
                            .animation(.linear(duration: 1).repeatForever(autoreverses: false), value: self.isProcessing)
                            .opacity(self.isProcessing ? 1 : 0)
                        
                        Text("Continue")
                            .opacity(self.isProcessing ? 0 : 1)
                            .frame(maxWidth:.infinity)
                    }
                }
                .padding()
                .foregroundColor(.white)
                .background(.blue)
                .cornerRadius(8)
                .disabled(self.isProcessing)
                .fullScreenCover(isPresented: $model.navigate) {
                    AuthenticatorView()
                }
                .alert(isPresented: $model.isPresentingErrorAlert,
                    content: {
                        Alert(title: Text("Alert"),
                              message: Text(model.errorMessage),
                              dismissButton: .cancel(Text("OK")))
                })
                
                Button {
                    dismiss()
                } label: {
                    Text("Cancel")
                        .frame(maxWidth:.infinity)
                }
                .padding(.top)
            }
            .padding(16)
        }
        .navigationBarBackButtonHidden(true)
        .onAppear {
            isFocused = true
        }
    }
}

struct RegistrationView_Previews: PreviewProvider {
    static var previews: some View {
        RegistrationView(code: "123abc")
    }
}


