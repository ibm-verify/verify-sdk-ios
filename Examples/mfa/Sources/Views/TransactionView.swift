//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import SwiftUI
import MFA

struct TransactionView: View {
    @Environment(\.dismiss) var dismiss
    @State private var isProcessingApproval = false
    @State private var isProcessingDeny = false
    @StateObject private var model: TransactionViewModel
    
    init(service: MFAServiceDescriptor, pendingTransaction: PendingTransactionInfo) {
        _model = StateObject(wrappedValue: TransactionViewModel(service: service, transactionInfo: pendingTransaction))
    }
    
    var body: some View {
        VStack {
            Text("Transaction")
                .font(.title)
                .padding()
            
            VStack(alignment: .leading) {
                Text(model.message)
                    .padding([.bottom], 16)
                
                Text("Identifier")
                    .fontWeight(.medium)
                    .padding([.bottom], 4)
                Text(model.transactionId)
                    .padding([.bottom], 16)
                
                Text("Attributes")
                    .fontWeight(.medium)
                    .padding([.top], 16)
                List {
                    ForEach(Array(model.transactionAttributes.keys.enumerated()), id:\.element) { value, key in
                        Section(header: Text(key.rawValue)) {
                            Text(model.transactionAttributes[key] ?? "Not available")
                        }
                    }
                }
            }
            .padding(16)
            
            Spacer()
            
            VStack {
                Button(action: {
                    Task {
                        self.isProcessingApproval.toggle()
                        await model.approveTransaction()
                        self.isProcessingApproval.toggle()
                        self.dismiss()
                    }
                }) {
                    ZStack {
                        Image("busy")
                            .rotationEffect(.degrees(self.isProcessingApproval ? 360.0 : 0.0))
                            .animation(.linear(duration: 1).repeatForever(autoreverses: false), value: self.isProcessingApproval)
                            .opacity(self.isProcessingApproval ? 1 : 0)
                        
                        Text("Approve")
                            .fontWeight(.medium)
                            .opacity(self.isProcessingApproval ? 0 : 1)
                            .frame(maxWidth:.infinity)
                    }
                }
                .padding()
                .foregroundColor(.white)
                .background(.blue)
                .cornerRadius(8)
                .disabled(self.isProcessingApproval)
                .alert(isPresented: $model.isPresentingErrorAlert,
                       content: {
                    Alert(title: Text("Alert"),
                          message: Text(model.errorMessage),
                          dismissButton: .cancel(Text("OK")))
                })
                
                Button(action: {
                    Task {
                        self.isProcessingDeny.toggle()
                        await model.denyTransaction()
                        self.isProcessingDeny.toggle()
                        self.dismiss()
                    }
                }) {
                    ZStack {
                        Image("busy")
                            .rotationEffect(.degrees(self.isProcessingDeny ? 360.0 : 0.0))
                            .animation(.linear(duration: 1).repeatForever(autoreverses: false), value: self.isProcessingDeny)
                            .opacity(self.isProcessingDeny ? 1 : 0)
                        
                        Text("Deny")
                            .fontWeight(.medium)
                            .opacity(self.isProcessingDeny ? 0 : 1)
                            .frame(maxWidth:.infinity)
                    }
                }
                .padding()
                .foregroundColor(.white)
                .background(.red)
                .cornerRadius(8)
                .disabled(self.isProcessingDeny)
                .alert(isPresented: $model.isPresentingErrorAlert,
                       content: {
                    Alert(title: Text("Alert"),
                          message: Text(model.errorMessage),
                          dismissButton: .cancel(Text("OK")))
                })
            }
            .padding(16)
        }
    }
}
