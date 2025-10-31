//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

class URLSessionDelegateHelperTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testSelfSignCertifcateValid() async throws {
        // Given
        let url = URL(string: "https://jsonplaceholder.typicode.com/posts/1")!
        
        // Where
        let session = URLSession(configuration: .default, delegate: SelfSignedCertificateDelegate(), delegateQueue: nil)
        let resource = HTTPResource<()>(.get, url: url)
        
        // Then
        do {
            let result: () = try await session.dataTask(for: resource)
            XCTAssertNotNil(result)
        }
        catch let error {
            XCTAssertFalse(false, error.localizedDescription)
        }
    }
    
    func testCertificatePinningInvalid() async throws {
        // Given
        let url = URL(string: "https://jsonplaceholder.typicode.com/posts/1")!
        let publicKeyCertificate = "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"
        
        let pinnedCertificate = PinnedCertificateDelegate(with: publicKeyCertificate)
        
        // Where
        let session = URLSession(configuration: .default, delegate: pinnedCertificate, delegateQueue: nil)
        let resource = HTTPResource<()>(.get, url: url)
        
        // Then
        do {
            let result: () = try await session.dataTask(for: resource)
            XCTAssertNotNil(result)
        }
        catch let error {
            XCTAssertFalse(false, error.localizedDescription)
        }
    }
    
    func testCertificatePinningValid() async throws {
        // Given
        let url = URL(string: "https://jsonplaceholder.typicode.com/posts/1")!
        let publicKeyCertificate = "MIIFODCCBN6gAwIBAgIQDyp6lxK+XXMFAk57ngzgqjAKBggqhkjOPQQDAjBKMQswCQYDVQQGEwJVUzEZMBcGA1UEChMQQ2xvdWRmbGFyZSwgSW5jLjEgMB4GA1UEAxMXQ2xvdWRmbGFyZSBJbmMgRUNDIENBLTMwHhcNMjEwNjI4MDAwMDAwWhcNMjIwNjI3MjM1OTU5WjB1MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEZMBcGA1UEChMQQ2xvdWRmbGFyZSwgSW5jLjEeMBwGA1UEAxMVc25pLmNsb3VkZmxhcmVzc2wuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEue3t/MQ9XSvGZMFTo7ZSVnu/4oar/5SX/ZzKETsjLYt0e5R/mQAT+tEBcwCzkDt08iDXR1PU+DNYpQf1EjmKfqOCA3kwggN1MB8GA1UdIwQYMBaAFKXON+rrsHUOlGeItEX62SQQh5YfMB0GA1UdDgQWBBSQanoOPWamtWp3WfVnJhDD8E3ptzA+BgNVHREENzA1ggx0eXBpY29kZS5jb22CFXNuaS5jbG91ZGZsYXJlc3NsLmNvbYIOKi50eXBpY29kZS5jb20wDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB7BgNVHR8EdDByMDegNaAzhjFodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vQ2xvdWRmbGFyZUluY0VDQ0NBLTMuY3JsMDegNaAzhjFodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vQ2xvdWRmbGFyZUluY0VDQ0NBLTMuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQICMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzB2BggrBgEFBQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBABggrBgEFBQcwAoY0aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Nsb3VkZmxhcmVJbmNFQ0NDQS0zLmNydDAMBgNVHRMBAf8EAjAAMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdgApeb7wnjk5IfBWc59jpXflvld9nGAK+PlNXSZcJV3HhAAAAXpTKCpbAAAEAwBHMEUCIHVlgulBqmCzyuw1nmcBLFSYHTz7Wyo2rfFObgQ/LbUHAiEA/kzrzGimKI/Vw+TQOtSRmDMPyk3N8OIYKAB6GMcGrNoAdwAiRUUHWVUkVpY/oS/x922G4CMmY63AS39dxoNcbuIPAgAAAXpTKCqfAAAEAwBIMEYCIQDdHeXhR9xTRXKZI9LFPdiXk2HRfOHqGcEqkAfjRnD22QIhALw/D9hK8wKkaKzVe0UKWsO57bkBVeR1BLpYS9Pi/+WDAHYAQcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYAAAF6UygqYAAABAMARzBFAiEAhypm+Quwbn3ASsjyZZ0nmuzAhr+qMQE2RXpek4/vzTYCICpsJGPX0OXXq6Pqd9pMSHCfbkp4K+kZCX/NziOrAk3EMAoGCCqGSM49BAMCA0gAMEUCIAzzcI29Cey6wEqEhVW/Be9WbsTXVqVrsDyTSfnPV0E6AiEAp/OJ7BCwZ1rIwZPGZpW7LT5wBs3ttE7FkIGoL83gQN4="
        
        let pinnedCertificate = PinnedCertificateDelegate(with: publicKeyCertificate)
        
        // Where
        let session = URLSession(configuration: .default, delegate: pinnedCertificate, delegateQueue: nil)
        let resource = HTTPResource<()>(.get, url: url)
        
        // Then
        do {
            let result: () = try await session.dataTask(for: resource)
            XCTAssertNotNil(result)
        }
        catch let error {
            XCTAssertFalse(false, error.localizedDescription)
        }
    }
    
    func testCertificatePinningNil() {
        // Given
        let publicKeyCertificate = "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        
        // When
        let pinnedCertificate = PinnedCertificateDelegate(with: publicKeyCertificate)
        
        // Then
        XCTAssertNil(pinnedCertificate)
    }
}
