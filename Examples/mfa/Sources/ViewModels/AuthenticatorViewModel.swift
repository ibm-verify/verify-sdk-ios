//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//


import Foundation
import MFA
import SwiftUI

@MainActor
class AuthenticatorViewModel: ObservableObject {
    private var dataManager: DataManager = DataManager()
    @Published var authenticator: (any MFAAuthenticatorDescriptor)? = nil
    
    var service: MFAServiceDescriptor?
    var pendingTransaction: PendingTransactionInfo?
    
    init() {
        if let authenticator = dataManager.load() {
            self.authenticator = authenticator
        }
    }
    
    @Published var errorMessage: String = String()
    @Published var isPresentingErrorAlert: Bool = false
    @Published var navigate: Bool = false
    
    func resetAuthenticator() {
        self.authenticator = nil
        try? dataManager.reset()
    }
    
    func saveAuthenticator() {
        do {
            try dataManager.save(authenticator: self.authenticator!)
        }
        catch let error {
            errorMessage = error.localizedDescription
            isPresentingErrorAlert = true
        }
    }
    
    private func refreshAuthenticator(authenticator: some MFAAuthenticatorDescriptor) async throws -> (any MFAAuthenticatorDescriptor) {
        print("refreshAuthenticator: Obtaining new token")
           
        // Refresh the OAuth token if required.
        do {
            let controller = MFAServiceController(using: authenticator)
            let service = controller.initiate()
            let token = try await service.refreshToken(using: authenticator.token.refreshToken!, accountName: authenticator.accountName, pushToken: "zxy123", additionalData: nil)
                
            var updateAuthenticator = authenticator
            updateAuthenticator.token = token
            return updateAuthenticator
        }
        catch let error {
            print("refreshAuthenticator: Error \(error.localizedDescription)")
            throw error
        }
    }

    func checkTransaction() async {
        print("checkTransaction: Resolving pending transactions")
        
        if var updateAuthenticator = self.authenticator {
            do {
                // Refresh the OAuth token if required.
                if updateAuthenticator.token.shouldRefresh {
                    updateAuthenticator = try await refreshAuthenticator(authenticator: updateAuthenticator)
                    self.authenticator = updateAuthenticator
                    saveAuthenticator()
                }
                
                // Create an instance of the service controller.
                let controller = MFAServiceController(using: updateAuthenticator)
                let service = controller.initiate()
                let transaction = try await service.nextTransaction(with: nil)
                
                print("Pending transaction count \(transaction.countOfPendingTransactions)")
                
                if let pendingTransaction = transaction.current {
                    self.service = service
                    self.pendingTransaction = pendingTransaction
                    self.navigate = true
                }
            }
            catch let error {
                print("checkTransaction: Error \(error.localizedDescription)")
                errorMessage = error.localizedDescription
                isPresentingErrorAlert = true
            }
        }
    }
}
