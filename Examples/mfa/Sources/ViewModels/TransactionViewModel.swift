//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import Foundation
import MFA
import Core
import CryptoKit
import SwiftUI

@MainActor
class TransactionViewModel: ObservableObject {
    private var dataManager: DataManager = DataManager()
    private let service: MFAServiceDescriptor
    private let transactionInfo: PendingTransactionInfo
    
    init(service: MFAServiceDescriptor, transactionInfo: PendingTransactionInfo) {
        self.service = service
        self.transactionInfo = transactionInfo
        
        self.message = transactionInfo.message
        self.transactionId = transactionInfo.shortId
        self.transactionAttributes = transactionInfo.additionalData
    }
    
    @Published var errorMessage: String = String()
    @Published var navigate: Bool = false
    @Published var isPresentingErrorAlert: Bool = false
    @Published var message: String = String()
    @Published var transactionId: String = String()
    @Published var transactionAttributes: [TransactionAttribute: String] = [:]
    
    // Approve a transaction
    func approveTransaction() async {
        guard let authenticator = dataManager.load() else {
            isPresentingErrorAlert = true
            errorMessage = "The authenticator was not found. Please try logging out and back in."
            return
        }
        
        let controller = MFAServiceController(using: authenticator)
        
        guard let factor = controller.transactionFactor(for: transactionInfo) else {
            isPresentingErrorAlert = true
            errorMessage = "The factor identifier was not found with the registered authenticator."
            return
        }
        
        do {
            // If you want to perform the private key extraction and signing, uncomment the following 2-lines.
            // let signedData = performDataSigning(factorType: factor)
            // try await self.service.completeTransaction(action: .verify, signedData: signedData)
            
            // This is the convenience way of completing a transaction where the MFA component performs the above 2-lines.
            try await self.service.completeTransaction(factor: factor)
        }
        catch {
            isPresentingErrorAlert = true
            errorMessage = error.localizedDescription
        }
    }
    
    // Deny a transaction
    func denyTransaction() async {
        guard let authenticator = dataManager.load() else {
            isPresentingErrorAlert = true
            errorMessage = "The authenticator was not found. Please try logging out and back in."
            return
        }
        
        guard let factor = authenticator.enrolledFactors.first(where: { $0.name == transactionInfo.keyName }) else {
            isPresentingErrorAlert = true
            errorMessage = "The factor identifier was not found with the registered authenticator."
            return
        }
        
        do {
            // This is the convenience way of completing a transaction.
            try await self.service.completeTransaction(action: .deny, factor: factor)
        }
        catch {
            isPresentingErrorAlert = true
            errorMessage = error.localizedDescription
        }
    }
    
    internal func performDataSigning(factorType: FactorType) -> String? {
        guard let result = factorType.nameAndAlgorithm else {
            return nil
        }

        do {
            let keyData = try KeychainService.default.readItem(result.name, searchType: .key)
            let privateKey = try RSA.Signing.PrivateKey(derRepresentation: keyData)

            let messageData = Data(transactionInfo.dataToSign.utf8)
            let digest = hash(messageData, using: result.algorithm)

            let signature = try privateKey.signature(for: digest)
            return signature.rawRepresentation.base64UrlEncodedString()

        } catch {
            // You may want to log the error here
            return nil
        }
    }

    private func hash(_ data: Data, using algorithm: SigningAlgorithm) -> Data {
        switch algorithm {
        case .sha384:
            return Data(SHA384.hash(data: data))
        case .sha512:
            return Data(SHA512.hash(data: data))
        default:
            return Data(SHA256.hash(data: data))
        }
    }
}
