//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import SwiftUI

struct EnrolmentView: View {
    @State var signatureImageName: String
    @State var name: String = String()
    
    var body: some View {
        HStack {
            Image(systemName: signatureImageName)
                .font(.title2)
            Text(name)
            Spacer(minLength: 16)
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor( .green)
                .font(.title2)
        }
    }
}

struct EnrolmentView_Previews: PreviewProvider {
    static var previews: some View {
        EnrolmentView(signatureImageName: "faceid", name: "Hello world 2")
    }
}
