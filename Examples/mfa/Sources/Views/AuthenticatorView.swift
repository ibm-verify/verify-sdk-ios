//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import SwiftUI
import MFA

struct AuthenticatorView: View {
    @Environment(\.dismiss) var dismiss
    @State private var isProcessing = false
    @State private var didReset = false
    @StateObject private var model: AuthenticatorViewModel = AuthenticatorViewModel()
    
    var body: some View {
        VStack {
            HStack {
                Spacer()
                Button {
                    Task {
                        self.isProcessing.toggle()
                        model.saveAuthenticator()
                        self.isProcessing.toggle()
                    }
                } label: {
                    Text("Update")
                        .fontWeight(.medium)
                }
                .padding(16)
                .disabled(self.isProcessing)
                .alert(isPresented: $model.isPresentingErrorAlert,
                    content: {
                        Alert(title: Text("Alert"),
                              message: Text(model.errorMessage),
                              dismissButton: .cancel(Text("OK")))
                })
            }
            
            Text("Authenticator")
                .font(.title)
                .padding()
                
            VStack(alignment: .leading) {
                Text("Service name")
                    .fontWeight(.medium)
                    .padding([.bottom], 4)
                Text(model.serviceName)
                    .padding([.bottom], 16)
                
                
                Text("Account nickname")
                    .fontWeight(.medium)
                    .padding([.bottom], 4)
                TextField("Account nickname", text: $model.accountName)
                    .frame(minHeight: 28)
                    .padding(10)
                    .overlay(RoundedRectangle(cornerRadius: 8)
                        .stroke(Color(.systemGray5), lineWidth: 1))
                
                Text("Enrolled factors")
                    .fontWeight(.medium)
                    .padding([.top], 16)
                List {
                    ForEach(model.factors, id: \.id) { factor in
                        EnrolmentView(success: true, name: factor.displayName)
                            .listRowSeparator(.hidden)
                    }
                }
                .listStyle(.plain)
            }
            .padding(16)
            
            Spacer()
            
            VStack {
                Button(action: {
                    Task {
                        self.isProcessing.toggle()
                        await model.checkTransaction()
                        self.isProcessing.toggle()
                    }
                }) {
                    ZStack {
                        Image("busy")
                            .rotationEffect(.degrees(self.isProcessing ? 360.0 : 0.0))
                            .animation(.linear(duration: 1).repeatForever(autoreverses: false), value: self.isProcessing)
                            .opacity(self.isProcessing ? 1 : 0)
                        
                        Text("Check Transaction")
                            .opacity(self.isProcessing ? 0 : 1)
                            .frame(maxWidth:.infinity)
                    }
                }
                .padding()
                .foregroundColor(.white)
                .background(.blue)
                .cornerRadius(8)
                .disabled(self.isProcessing)
                .sheet(isPresented: $model.navigate) {
                    TransactionView(service: model.service!, pendingTransaction: model.pendingTransaction!)
                }
                .alert(isPresented: $model.isPresentingErrorAlert,
                    content: {
                        Alert(title: Text("Alert"),
                              message: Text(model.errorMessage),
                              dismissButton: .cancel(Text("OK")))
                })
                
                Button {
                    resetAuthenticator()
                } label: {
                    Text("Reset")
                        .fontWeight(.medium)
                        .foregroundColor(.red)
                        .frame(maxWidth:.infinity)
                }
                .fullScreenCover(isPresented: $didReset) {
                    ContentView()
                }
                .padding(.top)
            }
            .padding(16)
        }
    }
}

extension AuthenticatorView {
    func resetAuthenticator() {
        model.resetAuthenticator()
        didReset.toggle()
        dismiss()
    }
}
