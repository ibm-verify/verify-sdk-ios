//
// Copyright contributors to the IBM Verify FIDO2 Sample App for iOS project
//

import Foundation
import UIKit
import os.log


class LandingViewController: UIViewController {
    @IBOutlet weak var buttonISVA: UIButton!
    @IBOutlet weak var buttonISV: UIButton!
    @IBOutlet weak var viewISVA: UIView!
    @IBOutlet weak var viewISV: UIView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Apply styling
        buttonISVA.setCornerRadius()
        buttonISV.setCornerRadius()
        viewISV.setCornerRadius()
        viewISVA.setCornerRadius()
        
        setTraitAppearance()
    }
    
    /// Called when the iOS interface environment changes.
    /// - parameter previousTraitCollection: The `UITraitCollection` object before the interface environment changed.
    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)

        if traitCollection.hasDifferentColorAppearance(comparedTo: previousTraitCollection) {
            setTraitAppearance()
        }
    }
        
    // Set the appearence based on the device trait appearance
    private func setTraitAppearance() {
        if traitCollection.userInterfaceStyle == .light {
            view.backgroundColor = UIColor(red: 0.969, green: 0.969, blue: 0.969, alpha: 1.0)
            viewISVA.backgroundColor = .systemBackground
            viewISV.backgroundColor = .systemBackground
        }
        else {
            view.backgroundColor = .clear
            viewISVA.backgroundColor = UIColor(red: 0.11, green: 0.11, blue: 0.11, alpha: 1.00)
            viewISV.backgroundColor = UIColor(red: 0.11, green: 0.11, blue: 0.11, alpha: 1.00)
        }
    }
}
