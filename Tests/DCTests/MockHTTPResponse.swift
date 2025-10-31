//
// Copyright contributors to the IBM Verify DC SDK for iOS project
//

import Foundation

/// A structure to represent a network response.
struct MockHTTPResponse {
    /// The metadata associated with the response to an HTTP protocol URL load request.
    let response: HTTPURLResponse
    
    /// The name of the resource storing the data.
    let fileResource: String
}

/// A  class that handles the loading of protocol-specific URL data.
class MockURLProtocol: URLProtocol {
    static var urls = [URL: MockHTTPResponse]()
    
    /// The binary data representing the JSON resource.
    static func loadFile(file resource: String) -> Data {
        guard let url = Bundle.module.url(forResource: resource, withExtension: "json", subdirectory: "Files") else {
            return Data()
        }
        return try! Data(contentsOf: url)
    }

    /// This method determines whether this protocol can handle the given request.
    /// - parameter request: A request to make canonical.
    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url else {
            return false
        }
        return urls.keys.contains(url)
    }

    /// This method returns a canonical version of the given request.
    /// - parameter request: A request to make canonical.
    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    /// Compares two requests for equivalence with regard to caching.
    /// - parameter request: A request to cache.
    override class func requestIsCacheEquivalent(_: URLRequest, to _: URLRequest) -> Bool {
        return false
    }
    
    /// Starts protocol-specific loading of a request.
    override func startLoading() {
        guard let client = client, let url = request.url, let mock = MockURLProtocol.urls[url] else {
            fatalError()
        }

        /// The binary data representing the JSON resource.
        var data: Data {
            get {
                let url = Bundle.module.url(forResource: mock.fileResource, withExtension: "json", subdirectory: "Files")!
                return try! Data(contentsOf: url)
            }
        }
        
        client.urlProtocol(self, didReceive: mock.response, cacheStoragePolicy: .notAllowed)
        client.urlProtocol(self, didLoad: data)
        client.urlProtocolDidFinishLoading(self)
    }

    /// Stops protocol-specific loading of a request.
    override func stopLoading() {
    }
}

