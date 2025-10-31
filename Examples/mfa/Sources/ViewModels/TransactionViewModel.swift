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
        if let authenticator = dataManager.load() {
            if let factorType = authenticator.allowedFactors.first(where: {$0.id == transactionInfo.factorID }) {
                do {
                    // Get the private key and sign the transaction data manually
                    //let signedData = performDataSigning(factorType: factorType)
                    
                    // Look at the denyTransaction function letting the SDK handle the key retrieval and signing.
                    //try await self.service.completeTransaction(action: .verify, signedData: signedData)
                    try await self.service.completeTransaction(action: .verify, factor: factorType)
                }
                catch let error {
                    isPresentingErrorAlert = true
                    errorMessage = error.localizedDescription
                }
            }
        }
    }
    
    // Deny a transaction
    func denyTransaction() async {
        if let authenticator = dataManager.load() {
            if let factorType = authenticator.allowedFactors.first(where: {$0.id == transactionInfo.factorID }) {
                do {
                    // This is the convenience way of completing a transaction.
                    try await self.service.completeTransaction(action: .deny, factor: factorType)
                }
                catch let error {
                    isPresentingErrorAlert = true
                    errorMessage = error.localizedDescription
                }
            }
        }
    }
    
    private func performDataSigning(factorType: FactorType) -> String {
        var hashAlgorithmType: HashAlgorithmType = .sha512
        var name: String = String()
        
        switch factorType {
        case .userPresence(let value):
            hashAlgorithmType = value.algorithm
            name = value.name
        case .face(let value):
            hashAlgorithmType = value.algorithm
            name = value.name
        case .fingerprint(let value):
            hashAlgorithmType = value.algorithm
            name = value.name
        default:
            break
        }
        
        do {
            let data = try KeychainService.default.readItem(name)
            let privateKey = try RSA.Signing.PrivateKey(derRepresentation: data)
            
            if hashAlgorithmType == .sha256 {
                let value = SHA256.hash(data:  Data(transactionInfo.dataToSign.utf8))
                let signature = try privateKey.signature(for: value)
                return signature.rawRepresentation.base64UrlEncodedString()
            }
            else if hashAlgorithmType == .sha384 {
                let value = SHA384.hash(data:  Data(transactionInfo.dataToSign.utf8))
                let signature = try privateKey.signature(for: value)
                return signature.rawRepresentation.base64UrlEncodedString()
            }
            else if hashAlgorithmType == .sha512 {
                let value = SHA512.hash(data:  Data(transactionInfo.dataToSign.utf8))
                let signature = try privateKey.signature(for: value)
                return signature.rawRepresentation.base64UrlEncodedString()
            }
            else {
                return ""
            }
        }
        catch {
            return ""
        }
    }
}
