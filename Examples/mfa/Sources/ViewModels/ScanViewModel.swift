//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//


import Foundation
import SwiftUI
import CodeScanner

class ScanViewModel: ObservableObject {
    @Published var code: String = String()
    @Published var errorMessage: String = String()
    @Published var navigate: Bool = false
    @Published var isPresentingErrorAlert: Bool = false
    
    // validate the scanned input
    func validate(result: Result<ScanResult, ScanError>) {
        switch result {
        case .success(let result):
            code = result.string
            navigate = true
        case .failure(let error):
            errorMessage = error.localizedDescription
            isPresentingErrorAlert = true
            navigate = false
        }
    }
}

