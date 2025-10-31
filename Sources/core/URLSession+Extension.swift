//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: Enums

/// An error that occurs during URLSession operations.
public enum URLSessionError: Error, Equatable {
    /// Returns a Boolean value indicating whether two values are equal.
    /// Equality is the inverse of inequality. For any values a and b, `a == b` implies that `a != b` is `false`.
    /// - Parameters:
    ///   - lhs: A value to compare.
    ///   - rhs: A value to compare.
    /// - Returns: A Boolean result.
    public static func == (lhs: URLSessionError, rhs: URLSessionError) -> Bool {
        guard type(of: lhs) == type(of: rhs) else { return false }
            let error1 = lhs as NSError
            let error2 = rhs as NSError
            return error1.domain == error2.domain && error1.code == error2.code
    }
    
    /// The response data was unexpectedly `nil`.
    case noData
    
    /// Unknown response returned from resource.
    case unknown
    
    /// The resource requires an authenticated credential.
    case unauthenticated
    
    /// An error occured establishing the networking connection.
    case transportFailed(Error)
    
    /// Parsing error occurred during encoding or decodong.
    case parsingFailed
    
    /// The resource returned an error.
    case invalidResource
    
    /// The response returned an error.
    /// - Parameters:
    ///   - statusCode: The `HTTPURLResponse.statusCode` value.
    ///   - description: The response description of the error.
    case invalidResponse(statusCode: Int, description: String)
}

/// Extension to `URLSessionError` for Localizing the error.
extension URLSessionError: LocalizedError {
    /// The localized error description.
    public var errorDescription: String? {
        switch self {
        case .noData:
            return NSLocalizedString(
                "The response data was unexpectedly nil.",
                comment: "No Data"
            )
        case .unknown:
            return NSLocalizedString(
                "Unknown response returned from endpoint.",
                comment: "Unknown"
            )
        case .unauthenticated:
            return NSLocalizedString(
                "The endpoint requires an authenticated credential.",
                comment: "Unauthenticated"
            )
        
        case .transportFailed(let error):
            return NSLocalizedString(
                "An error occured establishing the networking connection.\(error.localizedDescription)",
                comment: "Transport Failed"
            )
        case .parsingFailed:
            return NSLocalizedString(
                "Parsing error occurred during encoding or decodong.",
                comment: "Parsing Failed"
            )
        case .invalidResource:
            return NSLocalizedString(
                "The resource returned an error.",
                comment: "Invalid Resource"
            )
        case .invalidResponse(let statusCode, let description):
            return NSLocalizedString(String(statusCode), comment: description)
        }
    }
}

/// HTTP response status codes that are acceptable.
var acceptableStatusCodes: Range<Int> { 200..<300 }

// MARK: Helper Functions

/// Creates a URL encoded string for a query string or request body.
/// - Parameter params: The parameters to apply.
/// - Returns: The encoded string..
public func urlEncode(from params: [String: Any]) -> String {
    var components: [(String, String)] = []

    for key in params.keys.sorted(by: <) {
        let value = params[key]!
        components += queryComponents(fromKey: key, value: value)
    }

    return components.map { "\($0)=\($1)" }.joined(separator: "&")
}

/// Returns a percent-escaped, URL encoded query string components from a key-value pair.
/// - Parameter key: The key of the query component.
/// - Parameter value: The value of the query component.
/// - Returns: The percent-escaped, URL encoded query string components.
private func queryComponents(fromKey key: String, value: Any) -> [(String, String)] {
    var components: [(String, String)] = []

    if let dictionary = value as? [String: Any] {
        for (nestedKey, value) in dictionary {
            components += queryComponents(fromKey: "\(key)[\(nestedKey)]", value: value)
        }
    }
    else if let array = value as? [Any] {
        for value in array {
            components += queryComponents(fromKey: "\(key)[]", value: value)
        }
    }
    else if let value = value as? NSNumber {
        if value.isBool {
            components.append((key.urlFormEncodedString, value.boolValue ? "1" : "0"))
        }
        else {
            components.append((key.urlFormEncodedString, "\(value)".urlFormEncodedString))
        }
    }
    else if let bool = value as? Bool {
        components.append((key.urlFormEncodedString, bool ? "1" : "0"))
    }
    else {
        components.append((key.urlFormEncodedString, "\(value)".urlFormEncodedString))
    }

    return components
}


// MARK: - Structures

/// A HTTP resource contains a `URLRequest` and the ability to parse the response as a generic type.
public struct HTTPResource<T> {
    /// Represents information about the request.
    var request: URLRequest
    
    /// A function type that attempts to parse the response payload into a generic type.
    var parse: (Data?, URLResponse?) -> Result<T, Error>
    
    // MARK: - Initializers
    
    /// Create a new `HTTPResource` with request parameters.
    /// - Parameter method: The HTTP request method.
    /// - Parameter url: The URL of the request.
    /// - Parameter accept: The content type for the `Accept` header.
    /// - Parameter contentType: The content type for the `Content-Type` header.
    /// - Parameter body: The data sent as the message body of a request, such as for an HTTP POST request.
    /// - Parameter headers: A dictionary of additional HTTP header fields for a request.
    /// - Parameter timeOutInterval: The timeout interval for the request, in seconds. The default is 60.0.
    /// - Parameter queryParams: A dictionary of query items to append to the URL.
    /// - Parameter parse: A function type to transform `T`.
    public init(_ method: method = .get, url: URL, accept: ContentType? = nil, contentType: ContentType? = nil, body: Data? = nil, headers: [String: String] = [:], timeOutInterval: TimeInterval = 60, queryParams: [String: String] = [:], parse: @escaping (Data?, URLResponse?) -> Result<T, Error>) {
        
        var requestUrl: URL
        
        // Add the dictionary of query parameters to the URL.
        if queryParams.isEmpty {
            requestUrl = url
        }
        else {
            var component = URLComponents(url: url, resolvingAgainstBaseURL: true)!
            component.queryItems = component.queryItems ?? []
            component.queryItems!.append(contentsOf: queryParams.map { URLQueryItem(name: $0.key, value: $0.value) })
            requestUrl = component.url!
        }
        
        request = URLRequest(url: requestUrl)
        
        // Add the accept header.
        if let accept = accept {
            request.setValue(accept.rawValue, forHTTPHeaderField: "Accept")
        }
        
        // Add the content-type.
        if let contentType = contentType {
            request.setValue(contentType.rawValue, forHTTPHeaderField: "Content-Type")
        }
        
        // Add the additional headers.
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        request.timeoutInterval = timeOutInterval
        request.httpMethod = method.rawValue
        
        // Body property set last because of this issue: https://bugs.swift.org/browse/SR-6687
        request.httpBody = body

        self.parse = parse
    }
    
    /// Creates a new `HTTPResource` from a `URLRequest`.
    /// - Parameter request: The `URLRequest` to execute.
    /// - Parameter parse: A function type  to transforms `T`.
    public init(request: URLRequest, parse: @escaping (Data?, URLResponse?) -> Result<T, Error>) {
        self.request = request
        self.parse = parse
    }
    
    // MARK: - Functions
    
    /// Returns an HTTPResource containing the results of mapping the given closure over the sequence’s elements.
    /// - Parameter transform: A mapping closure. `transform` accepts an element of this sequence as its parameter and returns a transformed value of the same or of a different type.
    /// - Returns: A `HTTPResource` containing the transformed elements of this sequence.
    public func map<V>(_ transform: @escaping (T) -> V) -> HTTPResource<V> {
        return HTTPResource<V>(request: request, parse: { data, response in
            self.parse(data, response).map(transform)
        })
    }
}

// MARK: Extensions

extension HTTPResource where T == () {
    /// Creates a new `HTTPResource` without a parse transformation function.
    /// - Parameter method: The HTTP request method.
    /// - Parameter url: The URL of the request.
    /// - Parameter accept: The content type for the `Accept` header.  Default `application/json`.
    /// - Parameter contentType: The content type for the `Content-Type` header.  Default `application/json`.
    /// - Parameter body: The data sent as the message body of a request, such as for an HTTP POST request.
    /// - Parameter headers: A dictionary of additional HTTP header fields for a request.
    /// - Parameter timeOutInterval: The timeout interval for the request, in seconds. The default is 60.0.
    /// - Parameter queryParams: A dictionary of query items to append to the URL.
    public init(_ method: method = .get, url: URL, accept: ContentType? = nil, contentType: ContentType? = nil, body: Data? = nil, headers: [String: String] = [:],  timeOutInterval: TimeInterval = 60, queryParams: [String: String] = [:]) {
        self.init(method, url: url, accept: accept, contentType: contentType, body: body, headers: headers, timeOutInterval: timeOutInterval, queryParams: queryParams, parse: { _, _ in .success(()) })
    }
}

extension HTTPResource where T: Decodable {
    /// Creates a new `HTTPResource` for JSON operations that have an optional request body.
    /// - Parameter method: The HTTP request method.
    /// - Parameter url: The URL of the request.
    /// - Parameter accept: The content type for the `Accept` header.  Default `application/json`.
    /// - Parameter contentType: The content type for the `Content-Type` header.  Default `application/json`.
    /// - Parameter body: The JSON data sent as the message body of a request, such as for an HTTP POST request.
    /// - Parameter headers: A dictionary of additional HTTP header fields for a request.
    /// - Parameter timeOutInterval: The timeout interval for the request, in seconds. The default is 60.0.
    /// - Parameter queryParams: A dictionary of query items to append to the URL.
    /// - Parameter decoder: A deccoder used for decoding `T`.  Default is `JSONDecoder`.
    public init(json method: method, url: URL, accept: ContentType = .json,  contentType: ContentType = .json, body: Data? = nil, headers: [String: String] = [:], timeOutInterval: TimeInterval = 60, queryParams: [String: String] = [:], decoder: JSONDecoder = JSONDecoder()) {
        self.init(method, url: url, accept: accept, contentType: contentType, body: body, headers: headers, timeOutInterval: timeOutInterval, queryParams: queryParams) { data, _ in
            return Result {
                guard let data = data else {
                    throw URLSessionError.noData
                }
                
                return try decoder.decode(T.self, from: data)
            }
        }
    }

    /// Creates a new `HTTPResource` for JSON operations with an encodable body.
    /// - Parameter method: The HTTP request method.
    /// - Parameter url: The URL of the request.
    /// - Parameter accept: The content type for the `Accepts` header.  Default `application/json`.
    /// - Parameter body: The data sent as the message body of a request, such as for an HTTP POST.
    /// - Parameter headers: A dictionary of additional HTTP header fields for a request.
    /// - Parameter timeOutInterval: The timeout interval for the request, in seconds. The default is 60.0.
    /// - Parameter queryParams: A dictionary of query items to append to the URL.
    /// - Parameter decoder: A deccoder used for decoding `T`.  Default is `JSONDecoder`.
    /// - Parameter encoder: A encoder used for encoding `T`.  Default is `JSONEncoder`.
    public init<V: Encodable>(json method: method, url: URL, accept: ContentType = .json, body: V? = nil, headers: [String: String] = [:], timeOutInterval: TimeInterval = 60, queryParams: [String: String] = [:], decoder: JSONDecoder = JSONDecoder(), encoder: JSONEncoder = JSONEncoder()) {
        let value = body.map { try! encoder.encode($0) }
        
        self.init(method, url: url, accept: accept, contentType: .json, body: value, headers: headers, timeOutInterval: timeOutInterval, queryParams: queryParams) { data, _ in
            return Result {
                guard let data = data else {
                    throw URLSessionError.noData
                }
                
                return try decoder.decode(T.self, from: data)
            }
        }
    }
}

// MARK: - URLSession Extension
extension URLSession {
    /// Creates a task that retrieves the contents of the specified URL, then calls a handler upon completion.
    /// - Parameter resource: The `HTTPResource` containing the request.
    /// - Returns: The new session data task.
    @discardableResult
    public func dataTask<T>(for resource: HTTPResource<T>) async throws -> T {
        async let (data, response) = try await self.data(for: resource.request)
        
        guard let httpResponse = try await response as? HTTPURLResponse else {
            throw URLSessionError.unknown
        }
                        
        guard acceptableStatusCodes.contains(httpResponse.statusCode) else {
            if httpResponse.statusCode == 401 {
                throw URLSessionError.unauthenticated
            }
            
            let description = try await String(decoding: data, as: UTF8.self)
            throw URLSessionError.invalidResponse(statusCode: httpResponse.statusCode, description: description)
        }
        
        #if DEBUG
            let description = try await String(decoding: data, as: UTF8.self)
            print("--RESPONSE--\n")
            print("\tUrl:\n\(resource.request.url!)\n")
            print("\tBody:\n\(description)")
        #endif
        
        return try await resource.parse(data, httpResponse).get()
    }
}

// MARK: - Enums
/// HTTP method definitions.
/// See [https://tools.ietf.org/html/rfc7231#section-4.3](https://tools.ietf.org/html/rfc7231#section-4.3)
public enum method: String {
    /// The GET method requests transfer of a current selected representation for the target resource.
    case get = "GET"

    /// The POST method requests that the target resource process the representation enclosed in the request according to the resource's own specific semantics.
    case post = "POST"

    /// The PUT method requests that the state of the target resource be created or replaced with the state defined by the representation enclosed in the request message payload.
    case put = "PUT"

    /// The PATCH method requests that a set of changes described in the request entity be applied to the resource identified by the Request-URI.
    case patch = "PATCH"

    /// The DELETE method requests that the origin server remove the association between the target resource and its current functionality.
    case delete = "DELETE"
}

/// The `ContentType` is used to indicate the media type of the resource.
public enum ContentType: String {
    /// JSON format.
    case json = "application/json"
    /// XML format.
    /// - Remark: `application/xml` is recommended as of [RFC 7303](https://datatracker.ietf.org/doc/html/rfc7303#section-4.1)
    case xml = "application/xml"
    
    /// JPEG image format.
    /// - Remark: Used for `GET` methods.
    case jpeg = "image/jpeg"
    
    /// The keys and values are encoded in key-value tuples separated by '&', with a '=' between the key and the value.
    /// - Remark: Non-alphanumeric characters in both keys and values are percent encoded.
    case urlEncoded = "application/x-www-form-urlencoded"
}
