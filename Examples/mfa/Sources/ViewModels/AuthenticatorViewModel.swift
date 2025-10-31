//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//


import Foundation
import MFA
import SwiftUI

@MainActor
class AuthenticatorViewModel: ObservableObject {
    private var dataManager: DataManager = DataManager()
    private var authenticator: (any MFAAuthenticatorDescriptor)?
    
    var service: MFAServiceDescriptor?
    var pendingTransaction: PendingTransactionInfo?
    
    init() {
        if let authenticator = dataManager.load() {
            self.authenticator = authenticator
            self.accountName = authenticator.accountName
            self.serviceName = authenticator.serviceName
            self.factors = authenticator.allowedFactors
        }
    }
    
    @Published var errorMessage: String = String()
    @Published var isPresentingErrorAlert: Bool = false
    @Published var navigate: Bool = false
    @Published var accountName: String = String()
    @Published var serviceName: String = String()
    @Published var factors: [FactorType] = []
    
    func resetAuthenticator() {
        self.authenticator = nil
        try? dataManager.reset()
    }
    
    func saveAuthenticator() {
        if var updateAuthenticator = self.authenticator {
            updateAuthenticator.accountName = self.accountName
            
            do {
                try dataManager.save(authenticator: updateAuthenticator)
                self.authenticator = updateAuthenticator
            }
            catch let error {
                errorMessage = error.localizedDescription
                isPresentingErrorAlert = true
            }
        }
    }
    
    private func refreshAuthenticator(authenticator: some MFAAuthenticatorDescriptor) async throws -> (any MFAAuthenticatorDescriptor) {
        print("refreshAuthenticator: Obtaining new token")
           
        // Refresh the OAuth token if required.
        do {
            let controller = MFAServiceController(using: authenticator)
            let service = controller.initiate()
            let token = try await service.refreshToken(using: authenticator.token.refreshToken!, accountName: self.accountName, pushToken: "zxy123", additionalData: nil)
                
            var updateAuthenticator = authenticator
            updateAuthenticator.token = token
            updateAuthenticator.accountName = self.accountName
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
