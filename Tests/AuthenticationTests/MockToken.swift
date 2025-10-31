//
// Copyright contributors to the IBM Verify Authentication SDK for iOS project
//

import Foundation

/// A structure to represent a network response.
struct MockResponse {
    /// The metadata associated with the response to an HTTP protocol URL load request.
    let response: HTTPURLResponse
    
    /// A byte buffer in memory.
    let data: Data
}

/// A  class that handles the loading of protocol-specific URL data.
class MockURLProtocol: URLProtocol {
    static var urls = [URL: MockResponse]()

    /// This method determines whether this protocol can handle the given request.
    /// - parameter request: A request to make canonical.
    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url else { return false }
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

        client.urlProtocol(self, didReceive: mock.response, cacheStoragePolicy: .notAllowed)
        client.urlProtocol(self, didLoad: mock.data)
        client.urlProtocolDidFinishLoading(self)
    }

    /// Stops protocol-specific loading of a request.
    override func stopLoading() {
    }
}
