//
// Copyright contributors to the IBM Verify MFA Sample App for iOS project
//

import SwiftUI

struct EnrolmentView: View {
    @State var success = false
    @State var name: String = String()
    
    var body: some View {
        HStack {
            Image(systemName: success ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(success ? .green : .red)
                .font(.title2)
            Text(name)
        }
    }
}

struct EnrolmentView_Previews: PreviewProvider {
    static var previews: some View {
        EnrolmentView(success: true, name: "Hello world 2")
    }
}
