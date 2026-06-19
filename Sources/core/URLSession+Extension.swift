//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

import OSLog

private let logger = Logger(subsystem: "Core", category: "Networking")

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
        switch (lhs, rhs) {
        case (.unknown, .unknown), (.unauthenticated, .unauthenticated), (.parsingFailed, .parsingFailed), (.invalidResource, .invalidResource):
            return true
        case let (.transportFailed(lhsError), .transportFailed(rhsError)):
            return (lhsError as NSError).domain == (rhsError as NSError).domain && (lhsError as NSError).code == (rhsError as NSError).code
        case let (.invalidResponse(lhsCode, lhsDesc), .invalidResponse(rhsCode, rhsDesc)):
            return lhsCode == rhsCode && lhsDesc == rhsDesc
        default:
            return false
        }
    }
    
    /// Unknown response returned from resource.
    case unknown
    
    /// The resource requires an authenticated credential.
    case unauthenticated
    
    /// An error occurred establishing the networking connection.
    case transportFailed(Error)
    
    /// Parsing error occurred during encoding or decoding.
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
        case .unknown:
            return NSLocalizedString("Unknown response returned from endpoint.", comment: "Unknown")
        case .unauthenticated:
            return NSLocalizedString("The endpoint requires an authenticated credential.", comment: "Unauthenticated")
        case .transportFailed(let error):
            return NSLocalizedString("An error occurred establishing the networking connection.\(error.localizedDescription)", comment: "Transport Failed")
        case .parsingFailed:
            return NSLocalizedString("Parsing error occurred during encoding or decoding.", comment: "Parsing Failed")
        case .invalidResource:
            return NSLocalizedString("The resource returned an error.", comment: "Invalid Resource")
        case .invalidResponse(let statusCode, let description):
            return "\(statusCode): \(description)"
        }
    }
}

/// HTTP response status codes that are acceptable.
var acceptableStatusCodes: Range<Int> { 200..<400 }

// MARK: Helper Functions

/// Creates a URL encoded string for a query string or request body.
/// - Parameter params: The parameters to apply.
/// - Returns: The encoded string..
public func urlEncode(from params: [String: Any]) -> String {
    var components: [String] = []
    components.reserveCapacity(params.count) // Allocate memory once
    
    // Iterate the key-value pairs directly, sorting by the key
    for (key, value) in params.sorted(by: { $0.key < $1.key }) {
        appendQueryComponents(fromKey: key, value: value, to: &components)
    }
    
    return components.joined(separator: "&")
}

/// Returns a percent-escaped, URL encoded query string components from a key-value pair.
/// - Parameter key: The key of the query component.
/// - Parameter value: The value of the query component.
/// - Returns: The percent-escaped, URL encoded query string components.
private func appendQueryComponents(fromKey key: String, value: Any, to components: inout [String]) {
    if let dictionary = value as? [String: Any] {
        for (nestedKey, nestedValue) in dictionary {
            appendQueryComponents(fromKey: "\(key)[\(nestedKey)]", value: nestedValue, to: &components)
        }
    }
    else if let array = value as? [Any] {
        for arrayValue in array {
            appendQueryComponents(fromKey: "\(key)[]", value: arrayValue, to: &components)
        }
    }
    else if let number = value as? NSNumber {
        let stringValue = number.isBool ? (number.boolValue ? "1" : "0") : "\(number)".urlFormEncodedString
        components.append("\(key.urlFormEncodedString)=\(stringValue)")
    }
    else if let bool = value as? Bool {
        components.append("\(key.urlFormEncodedString)=\(bool ? "1" : "0")")
    }
    else {
        components.append("\(key.urlFormEncodedString)=\("\(value)".urlFormEncodedString)")
    }
}


// MARK: - Structures

/// A HTTP resource contains a `URLRequest` and the ability to parse the response as a generic type.
public struct HTTPResource<T> {
    /// Represents the URL request.
    public let request: URLRequest
    
    /// Parses a response payload into a generic type.
    ///
    /// - Parameters:
    ///   - data: Raw response payload. For `204 No Content`, this will be empty `Data()`.
    ///   - response: The non-optional response returned from `URLSession`.
    /// - Returns: Parsed result.
    public let parse: (Data, URLResponse) -> Result<T, Error>
    
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
    /// - Returns: A `Result` value that represents either a success or a failure, including an associated value in each case.
    public init(
        _ method: HTTPMethod = .get,
        url: URL,
        accept: HTTPContentType? = nil,
        contentType: HTTPContentType? = nil,
        body: Data? = nil,
        headers: [String: String]? = [:],
        timeOutInterval: TimeInterval = 60,
        queryParams: [String: String] = [:],
        parse: @escaping (Data, URLResponse) -> Result<T, Error>
    ) {
        var requestURL = url
        
        // Add the dictionary of query parameters to the URL.
        if !queryParams.isEmpty, var components = URLComponents(url: url, resolvingAgainstBaseURL: true) {
            var items = components.queryItems ?? []
            items.append(contentsOf: queryParams.map {
                URLQueryItem(name: $0.key, value: $0.value)
            })
            components.queryItems = items
            
            if let resolvedURL = components.url {
                requestURL = resolvedURL
            }
        }
        
        var request = URLRequest(
            url: requestURL,
            cachePolicy: .useProtocolCachePolicy,
            timeoutInterval: timeOutInterval
        )
        
        request.httpMethod = method.rawValue
        
        // Add the additional headers.
        if let headers {
            for (key, value) in headers {
                request.setValue(value, forHTTPHeaderField: key)
            }
        }
        
        // Add the accept header.
        if let accept {
            request.setValue(accept.rawValue, forHTTPHeaderField: "Accept")
        }
        
        // Add the content-type.
        if let contentType {
            request.setValue(contentType.rawValue, forHTTPHeaderField: "Content-Type")
        }
        
        // Body must be set last, refer: https://bugs.swift.org/browse/SR-6687
        request.httpBody = body

        self.request = request
        self.parse = parse
    }
    
    /// Creates a new `HTTPResource` from a `URLRequest`.
    /// - Parameter request: A URL request object that provides request-specific information such as the URL, cache policy, request type, and body data or body stream.
    /// - Parameter parse: A function type  to transforms `T`.
    public init(
            request: URLRequest,
            parse: @escaping (Data, URLResponse) -> Result<T, Error>
    ) {
        self.request = request
        self.parse = parse
    }
    
    // MARK: - Functions
    
    /// Returns an HTTPResource containing the results of mapping the given closure over the sequence’s elements.
    /// - Parameter transform: A mapping closure. `transform` accepts an element of this sequence as its parameter and returns a transformed value of the same or of a different type.
    /// - Returns: A `HTTPResource` containing the transformed elements of this sequence.
    public func map<V>(_ transform: @escaping (T) -> V) -> HTTPResource<V> {
        HTTPResource<V>(
            request: request,
            parse: { data, response in
                self.parse(data, response).map(transform)
            }
        )
    }
}

// MARK: Extensions

extension HTTPResource where T == Void {
    /// Creates a new `HTTPResource` without a parse transformation function.
    /// - Parameter method: The HTTP request method.
    /// - Parameter url: The URL of the request.
    /// - Parameter accept: The content type for the `Accept` header.  Default `application/json`.
    /// - Parameter contentType: The content type for the `Content-Type` header.  Default `application/json`.
    /// - Parameter body: The data sent as the message body of a request, such as for an HTTP POST request.
    /// - Parameter headers: A dictionary of additional HTTP header fields for a request.
    /// - Parameter timeOutInterval: The timeout interval for the request, in seconds. The default is 60.0.
    /// - Parameter queryParams: A dictionary of query items to append to the URL.
    public init(
        _ method: HTTPMethod = .get,
        url: URL,
        accept: HTTPContentType? = nil,
        contentType: HTTPContentType? = nil,
        body: Data? = nil,
        headers: [String: String] = [:],
        timeOutInterval: TimeInterval = 60,
        queryParams: [String: String] = [:]
    ) {
        self.init(
            method,
            url: url,
            accept: accept,
            contentType: contentType,
            body: body,
            headers: headers,
            timeOutInterval: timeOutInterval,
            queryParams: queryParams
        ) { _, _ in
            .success(())
        }
    }
}

extension HTTPResource where T: Decodable {
    
    /// Creates a new `HTTPResource` for JSON operations with an optional raw body.
    ///
    /// - Parameters:
    ///   - method: The HTTP request method.
    ///   - url: The target URL.
    ///   - accept: The `Accept` header value. Defaults to JSON.
    ///   - contentType: The `Content-Type` header value. Defaults to JSON.
    ///   - body: Optional raw request body.
    ///   - headers: Additional HTTP headers.
    ///   - timeOutInterval: Timeout in seconds.
    ///   - queryParams: Query items appended to the URL.
    ///   - decoder: JSON decoder used to decode the response.
    public init(
        json method: HTTPMethod,
        url: URL,
        accept: HTTPContentType = .json,
        contentType: HTTPContentType = .json,
        body: Data? = nil,
        headers: [String: String] = [:],
        timeOutInterval: TimeInterval = 60,
        queryParams: [String: String] = [:],
        decoder: JSONDecoder = JSONDecoder()
    ) {
        self.init(
            method,
            url: url,
            accept: accept,
            contentType: contentType,
            body: body,
            headers: headers,
            timeOutInterval: timeOutInterval,
            queryParams: queryParams
        ) { data, _ in
            Result {
                do {
                    return try decoder.decode(T.self, from: data)
                }
                catch {
                    logger.error("HTTPResource: Decoding failed - \(error.localizedDescription)")
                    throw URLSessionError.parsingFailed
                }
            }
        }
    }

    /// Creates a new `HTTPResource` for JSON operations with an encodable request body.
    ///
    /// - Parameters:
    ///   - method: The HTTP request method.
    ///   - url: The target URL.
    ///   - accept: The `Accept` header value. Defaults to JSON.
    ///   - body: Encodable request body.
    ///   - headers: Additional HTTP headers.
    ///   - timeOutInterval: Timeout in seconds.
    ///   - queryParams: Query items appended to the URL.
    ///   - decoder: JSON decoder used for decoding responses.
    ///   - encoder: JSON encoder used for encoding request bodies.
    public init<V: Encodable>(
        json method: HTTPMethod,
        url: URL,
        accept: HTTPContentType = .json,
        body: V? = nil,
        headers: [String: String] = [:],
        timeOutInterval: TimeInterval = 60,
        queryParams: [String: String] = [:],
        decoder: JSONDecoder = JSONDecoder(),
        encoder: JSONEncoder = JSONEncoder()
    ) {
        let encodedBody: Data?
        
        do {
            encodedBody = try body.map { try encoder.encode($0) }
        }
        catch {
            logger.error("HTTPResource: Failed to encode request body - \(error.localizedDescription)")
            encodedBody = nil
        }
        
        self.init(
            json: method,
            url: url,
            accept: accept,
            contentType: .json,
            body: encodedBody,
            headers: headers,
            timeOutInterval: timeOutInterval,
            queryParams: queryParams,
            decoder: decoder
        )
    }
}

extension URLSession {
    /// Creates a task that retrieves the contents of the specified URL, logs the transaction, and parses the response.
    ///
    /// This method performs the network request asynchronously, tracks latency, logs request/response details (with detailed body logging in DEBUG builds), and validates the HTTP status code. If the status code is unacceptable, it attempts to extract a meaningful error description from the payload.
    ///
    /// - Parameters:
    ///   - resource: The `HTTPResource` containing the request configuration and parsing logic.
    /// - Returns: The parsed response of generic type `T`.
    /// - Throws: `URLSessionError` for network failures, invalid responses, or unauthenticated requests.
    @discardableResult
    public func dataTask<T>(for resource: HTTPResource<T>) async throws -> T {
        // Cache computationally expensive or repetitive properties
        let requestId = UUID()
        let urlString = resource.request.url?.absoluteString ?? "N/A"
        let method = resource.request.httpMethod ?? "N/A"
        
        logger.info("URLSession.dataTask - ENTRY")
        
        defer {
            logger.info("URLSession.dataTask - EXIT")
        }
        
        logger.debug("⬆️ Request [\(requestId)]: Method: \(method), URL: \(urlString)")
        
        #if DEBUG
        if let headers = resource.request.allHTTPHeaderFields {
            logger.debug("➡️ Request [\(requestId)] Headers: \(headers)")
        }
        
        if let data = resource.request.httpBody {
            // String(decoding:as:) is highly optimized and avoids optional allocation
            logger.debug("➡️ Request [\(requestId)] Body: \(String(decoding: data, as: UTF8.self))")
        }
        #endif
        
        // Use Date() for latency tracking
        let startTime = Date()
        
        let data: Data
        let response: URLResponse
        
        do {
            // Direct suspension point — highly performant, no background task overhead
            (data, response) = try await self.data(for: resource.request)
        }
        catch {
            let latency = Date().timeIntervalSince(startTime)
            logger.error("❌ Network Error [\(requestId)]: URL: \(urlString), Latency: \(String(format: "%.3f", latency))s, Error: \(error.localizedDescription)")
            
            throw error
        }
        
        let latency = Date().timeIntervalSince(startTime)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            logger.error("❌ Response [\(requestId)] Error: Unknown response type for URL: \(urlString), Latency: \(String(format: "%.3f", latency))s")
            throw URLSessionError.unknown
        }
        
        let statusCode = httpResponse.statusCode
        logger.info("⬇️ Response [\(requestId)]: Status: \(statusCode), URL: \(urlString), Latency: \(String(format: "%.3f", latency))s")
        
        #if DEBUG
        if let headers = httpResponse.allHeaderFields as? [String: Any] {
            logger.debug("⬅️ Response [\(requestId)] Headers: \(headers)")
        }
        
        if !data.isEmpty {
            let bodyString = String(decoding: data, as: UTF8.self)
            logger.debug("⬅️ Response [\(requestId)] Body: \(bodyString)")
        }
        #endif
        
        guard acceptableStatusCodes.contains(statusCode) else {
            let description = extractErrorDescription(from: data)
            
            logger.error("❌ Response [\(requestId)] Error: Unacceptable Status Code: \(statusCode) for URL: \(urlString), Description: \(description)")
            
            if statusCode == 401 {
                throw URLSessionError.unauthenticated
            }
            
            throw URLSessionError.invalidResponse(statusCode: statusCode, description: description)
        }
        
        logger.info("✅ Success [\(requestId)]: Parsed data for URL: \(urlString)")
        
        return try resource.parse(data, httpResponse).get()
    }
    
    /// Extracts an error description from the response data efficiently.
    ///
    /// It first attempts a lightweight JSON Serialization to find `error_description` or `messageDescription`.
    /// If neither is found or the data is not valid JSON, it falls back to a raw UTF-8 string conversion.
    ///
    /// - Parameter data: The raw error payload from the server.
    /// - Returns: A string representing the extracted error message.
    private func extractErrorDescription(from data: Data) -> String {
        // Immediately return if there is no payload to parse, saving processing time
        guard !data.isEmpty else { return "Empty Response" }
        
        // JSONSerialization is the fastest method for shallow, top-level dictionary lookups
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            
            if let errorDescription = json["message"] as? String {
                return errorDescription
            }
            
            if let errorDescription = json["error_description"] as? String {
                return errorDescription
            }
            
            if let errorDescription = json["messageDescription"] as? String {
                return errorDescription
            }
        }
        
        // Fallback using the high-performance decoding initializer
        return String(decoding: data, as: UTF8.self)
    }
}

// MARK: - Enums
/// HTTP method definitions.
/// See [https://tools.ietf.org/html/rfc7231#section-4.3](https://tools.ietf.org/html/rfc7231#section-4.3)
public enum HTTPMethod: String {
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
public enum HTTPContentType: String {
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
