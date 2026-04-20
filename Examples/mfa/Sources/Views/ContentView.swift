//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import SwiftUI
import CodeScanner
import MFA

struct ContentView: View {
    var dataManager: DataManager = DataManager()
    
    @ObservedObject private var model: ScanViewModel = ScanViewModel()
    @State private var isPresented: Bool = false
    
    // Simulator data.  NOTE: JSON has been obtained from QR code.
    private let json = """
    {
        "code":"P8BEzUM3mE1amKMF76f3BOLTdCkgq_v70ZNCIl41tGZ.PIz1kyA31M3ttCkl4FfNg7vNKhauXizO.PmyQjlH0uRAmQT2ukQIbKJ38P.sexlfiyyv4gPdgrl1K9UXalcTAg",
        "accountName":"johndoe",
        "registrationUri":"https://sdk.verify.ibm.com/v1.0/authenticators/registration",
        "version":{
            "number":"1.0.0",
            "platform":"com.ibm.security.access.verify"
        }
    }
    """
    
    var body: some View {
        if dataManager.exists() {
            AuthenticatorView()
        }
        else {
            VStack {
                VStack {
                    Text("MFA sample")
                        .font(.title)
                        .padding()
                    Text("This sample app demonstrates registering an authenticator for multi-factor authentication.")
                        .font(.title2)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }.padding(16)
                
                Spacer()
                
                VStack {
                    Button(action: {
                        isPresented.toggle()
                    }, label: {
                        Text("Get Started")
                            .fontWeight(.medium)
                            .frame(maxWidth:.infinity)
                    })
                    .padding()
                    .foregroundColor(.white)
                    .background(.blue)
                    .cornerRadius(8)
                    .sheet(isPresented: $isPresented) {
                        CodeScannerView(codeTypes: [.qr], simulatedData: json) { result in
                            model.validate(result: result)
                            isPresented.toggle()
                        }
                    }
                    .sheet(isPresented: $model.navigate) {
                        RegistrationView(code: model.code)
                    }
                    .alert(isPresented: $model.isPresentingErrorAlert,
                           content: {
                        Alert(title: Text("Alert"),
                              message: Text(model.errorMessage),
                              dismissButton: .cancel(Text("OK")))
                    })
                }.padding(16)
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
