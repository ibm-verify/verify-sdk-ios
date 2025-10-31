//
// Copyright contributors to the IBM Verify Core SDK for iOS project
//

import XCTest
@testable import Core

class URLSessionExtensionTests: XCTestCase {
    /// - Remark: The URL for posts contains 100 items.
    let url = URL(string: "https://jsonplaceholder.typicode.com/posts")!
    
    // Static Post objects
    let newPost = Post(userId: 201, id: 201, title: "Test Core", body: "Test post body.")
    let updatePost = Post(userId: 1, id: 1, title: "Test Core", body: "Test post body.")

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    struct Post: Codable {
        var userId: Int
        var id: Int
        var title: String
        var body: String
    }
    
    // MARK:- Initializer tests
    
    /// Get an array todo items.
    func testInitJsonAll() async throws {
        // Given
        let resource = HTTPResource<[Post]>(json: .get, url: url)
        
        // Where, Then
        do {
            let result = try await URLSession.shared.dataTask(for: resource)
            XCTAssertTrue(result.count == 100)
        }
        catch let error {
            XCTAssertFalse(false, error.localizedDescription)
        }
    }
    
    /// Get the first todo items.
    func testInitJsonFirst() async throws {
        // Given
        let url = self.url.appendingPathComponent("1")
        let resource = HTTPResource<Post>(json: .get, url: url)
        
        // Where, Then
        do {
            let result = try await URLSession.shared.dataTask(for: resource)
            XCTAssertNotNil(result)
        }
        catch let error {
            XCTAssertFalse(false, error.localizedDescription)
        }
    }
    
    /// Get an array todo items to map titles.
    func testInitJsonFilter() async throws {
        // Given
        let resource = HTTPResource<[Post]>(json: .get, url: url, queryParams: ["userId": "1"])
        
        // Where, Then
        do {
            let result = try await URLSession.shared.dataTask(for: resource)
            XCTAssertTrue(result.count == 10)
        }
        catch let error {
            XCTAssertFalse(false, error.localizedDescription)
        }
    }
    
    
    /// Get an array posts items to map to the first item.
    func testInitJsonMap() async throws {
        // Given
        let posts = HTTPResource<[Post]>(json: .get, url: url)
        let firstPost = posts.map{ $0.first }
        
        // Where
        do {
            let result = try await URLSession.shared.dataTask(for: firstPost)
            XCTAssertEqual(result?.id, 1)
        }
        catch let error {
            XCTAssertFalse(false, error.localizedDescription)
        }
    }
    
    /// Get an array todo items with request and parse.
    func testInitAllRequestAndParse() async throws {
        // Given
        let request = URLRequest(url: url)
        let resource = HTTPResource<[Post]>(request: request, parse: { data, response in
            do {
                let value = try JSONDecoder().decode([Post].self, from: data!)
                return Result.success(value)
            }
            catch let error {
                return Result.failure(error)
            }
        })
        
        // Where
        do {
            let result = try await URLSession.shared.dataTask(for: resource)
            let titles = result.map { $0.title }
            XCTAssertEqual(titles.count, 100)
        }
        catch let error {
            XCTAssertFalse(false, error.localizedDescription)
        }
    }
    
    /// Tests overloaded init with a PUT.
    func testInitJsonMinimumParams() async throws {
        // Given
        let url = self.url.appendingPathComponent("1")
        let resource = HTTPResource<Post>(json: .put, url: url, body: updatePost)
        
        // Where, Then
        do {
            let result = try await URLSession.shared.dataTask(for: resource)
            XCTAssertEqual(result.body, self.newPost.body)
        }
        catch let error {
            XCTAssertFalse(true, error.localizedDescription)
        }
    }
    
    /// Tests overloaded init with a PATCH.
    func testInitJsonAllParams() async throws {
        // Given
        let url = self.url.appendingPathComponent("1")
        
        struct PostTitle: Encodable {
            var title: String
        }
        
        let updateTitle = PostTitle(title: "Update Test Core")
        
        let resource = HTTPResource<Post>(json: .patch, url: url, accept: .json, body: updateTitle, timeOutInterval: 15, decoder: JSONDecoder(), encoder: JSONEncoder())
        
        // Where
        do {
            let result = try await URLSession.shared.dataTask(for: resource)
            XCTAssertEqual(result.title, updateTitle.title)
        }
        catch let error {
            XCTAssertFalse(true, error.localizedDescription)
        }
    }
    
    /// Tests overloaded init JSON with an encoder.
    func testInitJsonEncoder() async throws {
        // Given
        let url = self.url.appendingPathComponent("1")
        
        let encoder = JSONEncoder()
        encoder.dataEncodingStrategy = .deferredToData
        
        let resource = HTTPResource<Post>(json: .put, url: url, accept: .json, body: updatePost, headers: ["header1": "header1", "header2": "header2"], timeOutInterval: 15, queryParams: ["userId":"1"], encoder: encoder)
        
        // Where, Then
        do {
            let result = try await URLSession.shared.dataTask(for: resource)
            XCTAssertEqual(result.title, "Test Core")
        }
        catch let error {
            XCTAssertFalse(true, error.localizedDescription)
        }
    }
    
    
    /// Tests overloaded init with a DELETE.
    func testInitMinimumParams() async throws {
        // Given
        let url = self.url.appendingPathComponent("1")
        let resource = HTTPResource(.delete, url: url)
        
        // Where
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTAssertTrue(true)
        }
        catch let error {
            XCTAssertFalse(true, error.localizedDescription)
        }
    }
    
    
    /// Tests overloaded init with a POST.
    func testInitAllParamsFilter() async throws {
        // Given
        let body = try! JSONEncoder().encode(newPost)
        
        let resource = HTTPResource<()>(.post, url: url, accept: .json, contentType: .json, body: body, headers: ["header1": "header1", "header2": "header2"], timeOutInterval: 15, queryParams: [:])
        
        // Where
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTAssertTrue(true)
        }
        catch let error {
            XCTAssertFalse(true, error.localizedDescription)
        }
    }
    
    /// Tests overloaded init with a PATCH.
    func testInitAllParams() async throws {
        // Given
        let url = self.url.appendingPathComponent("1")
        let body = """
            {
                "title": "Update post"
            }
        """
      
        // Where
        let resource = HTTPResource<Post>(.patch, url: url, accept: .json, contentType: .json, body: body.data(using: .utf8), headers: ["header1": "header1", "header2": "header2"], timeOutInterval: 15, queryParams: [:], parse: { data, response in
            do {
                let value = try JSONDecoder().decode(Post.self, from: data!)
                return Result.success(value)
            }
            catch let error {
                return Result.failure(error)
            }
        })
        
        // Then
        do {
            let result = try await URLSession.shared.dataTask(for: resource)
            XCTAssertEqual(result.title, "Update post")
        }
        catch let error {
            XCTAssertFalse(true, error.localizedDescription)
        }
    }
    
    
    /// Tests overloaded init returning an UIImage
    func testInitImageResource() async throws {
        // Given
        let url = URL(string: "https://picsum.photos/200")!
        let resource = HTTPResource<UIImage>(.get, url: url, accept: .jpeg) { data, response in
            return Result {
                guard let data = data, let image = UIImage(data: data) else {
                    throw URLSessionError.noData
                }
                
                return image
            }
        }
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTAssertTrue(true)
        }
        catch let error {
            XCTAssertFalse(true, error.localizedDescription)
        }
    }
    
    /// Tests overloaded init returning an UIImage of invalid size
    func testInitInvalidImageResource() async throws {
        // Given
        let url = URL(string: "https://picsum.photos/id/0/5616/3744")!
        let resource = HTTPResource<UIImage>(.get, url: url, accept: .jpeg) { data, response in
            return Result {
                guard let data = data, let image = UIImage(data: data) else {
                    throw URLSessionError.noData
                }
                
                return image
            }
        }
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    
    // MARK: - Error handling
    
    static func throwError(_ error: URLSessionError) throws {
        throw error
    }
    
    /// Tests no data error
    func testURLSessionErrorNoData() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try URLSessionExtensionTests.throwError(.noData)) {
            thrownError = $0
        }

        // Then
        XCTAssertTrue(thrownError is URLSessionError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? URLSessionError, .noData)
        
        // Then
        XCTAssertEqual(thrownError?.localizedDescription, URLSessionError.noData.localizedDescription)
    }
    
    /// Tests unknown error
    func testURLSessionErrorUnknown() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try URLSessionExtensionTests.throwError(.unknown)) {
            thrownError = $0
        }

        // Then
        XCTAssertTrue(thrownError is URLSessionError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? URLSessionError, .unknown)
        
        // Then
        XCTAssertEqual(thrownError?.localizedDescription, URLSessionError.unknown.localizedDescription)
    }
    
    /// Tests unauthenticated error
    func testURLSessionErrorUnauthenticated() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try URLSessionExtensionTests.throwError(.unauthenticated)) {
            thrownError = $0
        }

        // Then
        XCTAssertTrue(thrownError is URLSessionError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? URLSessionError, .unauthenticated)
        
        // Then
        XCTAssertEqual(thrownError?.localizedDescription, URLSessionError.unauthenticated.localizedDescription)
    }
    
    /// Tests transport failed error
    func testURLSessionErrorTransportFailed() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try URLSessionExtensionTests.throwError(.transportFailed(NSError(domain: "URLSessionError", code: -1)))) {
            thrownError = $0
        }

        // Then
        XCTAssertTrue(thrownError is URLSessionError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? URLSessionError, .transportFailed(NSError(domain: "URLSessionError", code: -1)))
        
        // Then
        XCTAssertEqual(thrownError?.localizedDescription, URLSessionError.transportFailed(NSError(domain: "URLSessionError", code: -1)).localizedDescription)
    }
    
    /// Tests parsingFailed error
    func testURLSessionErrorParsingFailed() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try URLSessionExtensionTests.throwError(.parsingFailed)) {
            thrownError = $0
        }

        // Then
        XCTAssertTrue(thrownError is URLSessionError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? URLSessionError, .parsingFailed)
        
        // Then
        XCTAssertEqual(thrownError?.localizedDescription, URLSessionError.parsingFailed.localizedDescription)
    }
    
    /// Tests invalidResource error
    func testURLSessionErrorInvalidResource() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try URLSessionExtensionTests.throwError(.invalidResource)) {
            thrownError = $0
        }

        // Then
        XCTAssertTrue(thrownError is URLSessionError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? URLSessionError, .invalidResource)
        
        // Then
        XCTAssertEqual(thrownError?.localizedDescription, URLSessionError.invalidResource.localizedDescription)
    }
    
    /// Tests invalidResponse error
    func testURLSessionErrorInvalidResponse() throws {
        // Given
        var thrownError: Error?

        // When
        XCTAssertThrowsError(try URLSessionExtensionTests.throwError(.invalidResponse(statusCode: 404, description: "Resource not found"))) {
            thrownError = $0
        }

        // Then
        XCTAssertTrue(thrownError is URLSessionError, "Unexpected error type: \(type(of: thrownError))")

        // Then
        XCTAssertEqual(thrownError as? URLSessionError, .invalidResponse(statusCode: 404, description: "Resource not found"))
        
        // Then
        XCTAssertEqual(thrownError?.localizedDescription, URLSessionError.invalidResponse(statusCode: 404, description: "Resource not found").localizedDescription)
    }
    
    /// Tests unauthenticated error responses
    func testDataTaskUnauthenticated() async throws {
        // Given
        let url = URL(string: "https://api.github.com")!
        let resource = HTTPResource<()>(.get, url: url, headers: ["Authorization": "Bearer abc123"])
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTFail("A response in the 200 range was not expected.")
        }
        catch let error {
            XCTAssertEqual(error as? URLSessionError, URLSessionError.unauthenticated)
        }
    }
    
    /// Tests invalid response 404 error.
    func testDataTaskInvalidResponse() async throws {
        // Given
        let url = URL(string: "https://api.github.com")!
        let resource = HTTPResource<()>(.post, url: url)
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTFail("A response in the 200 range was not expected.")
        }
        catch let error {
            XCTAssertEqual(error as? URLSessionError, URLSessionError.invalidResponse(statusCode: 404, description: "Resource not found"))
        }
    }
    
    /// Tests transport failed due to the host being invalid.
    func testDataTaskTransportFailed() async throws {
        // Given
        let url = URL(string: "https://nohost.com")!
        let resource = HTTPResource<()>(.get, url: url)
        
        // Where, Then
        do {
            let _ = try await URLSession.shared.dataTask(for: resource)
            XCTFail("A response in the 200 range was not expected.")
        }
        catch let error {
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }

    // MARK: Encoding Tests - Parameter Types
    func testURLParameterEncodeEmptyDictionary() {
        // Given
        let parameters: [String: Any] = [:]
            
        // When
        let result = urlEncode(from: parameters)
            
        // Then
        XCTAssert(result.isEmpty)
    }
    
    func testURLParameterEncodeOneStringKeyStringValue() {
        // Given
        let parameters = ["foo": "bar"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "foo=bar")
    }
    
    func testURLParameterEncodeTwoStringKeyStringValue() {
        // Given
        let parameters = ["foo": "bar", "baz": "qux"]
            
        // When
        let result = urlEncode(from: parameters)
            
        // Then
        XCTAssertEqual(result, "baz=qux&foo=bar")
    }
    
    func testURLParameterEncodeStringKeyNSNumberIntegerValue() {
        // Given
        let parameters = ["foo": NSNumber(value: 25)]
            
        // When
        let result = urlEncode(from: parameters)
            
        // Then
        XCTAssertEqual(result, "foo=25")
    }
    
    func testURLParameterEncodeStringKeyNSNumberBoolValue() {
        // Given
        let parameters = ["foo": NSNumber(value: false)]
            
        // When
        let result = urlEncode(from: parameters)
            
        // Then
        XCTAssertEqual(result, "foo=0")
    }
    
    func testURLParameterEncodeStringKeyIntegerValue() {
        // Given
        let parameters = ["foo": 1]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "foo=1")
    }
    
    func testURLParameterEncodeStringKeyDoubleValue() {
        // Given
        let parameters = ["foo": 1.1]
        
        // When
        let result = urlEncode(from: parameters)
            
        // Then
        XCTAssertEqual(result, "foo=1.1")
    }
    
    func testURLParameterEncodeStringKeyBoolValue() {
        // Given
        let parameters = ["foo": true]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "foo=1")
    }
    
    func testURLParameterEncodeStringKeyArrayValue() {
        // Given
        let parameters = ["foo": ["a", 1, true]]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "foo%5B%5D=a&foo%5B%5D=1&foo%5B%5D=1")
    }
    
    func testURLParameterEncodeStringKeyDictionaryValue() {
        // Given
        let parameters = ["foo": ["bar": 1]]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "foo%5Bbar%5D=1")
    }
    
    func testURLParameterEncodeStringKeyNestedDictionaryValue() {
        // Given
        let parameters = ["foo": ["bar": ["baz": 1]]]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "foo%5Bbar%5D%5Bbaz%5D=1")
    }
    
    func testURLParameterEncodeStringKeyNestedDictionaryArrayValueP() {
        // Given
        let parameters = ["foo": ["bar": ["baz": ["a", 1, true]]]]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        let expectedQuery = "foo%5Bbar%5D%5Bbaz%5D%5B%5D=a&foo%5Bbar%5D%5Bbaz%5D%5B%5D=1&foo%5Bbar%5D%5Bbaz%5D%5B%5D=1"
       
        XCTAssertEqual(result, expectedQuery)
    }
    
    // MARK: Tests - All Reserved / Unreserved / Illegal Characters According to RFC 3986
    
    func testThatReservedCharactersArePercentEscapedMinusQuestionMarkAndForwardSlash() {
        // Given
        let generalDelimiters = ":#[]@"
        let subDelimiters = "!$&'()*+,;="
        let parameters = ["reserved": "\(generalDelimiters)\(subDelimiters)"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        let expectedQuery = "reserved=%3A%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D"
        XCTAssertEqual(result, expectedQuery)
    }
    
    func testThatReservedCharactersQuestionMarkAndForwardSlashAreNotPercentEscaped() {
        // Given
        let parameters = ["reserved": "?/"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "reserved=?/")
    }
    
    func testThatUnreservedNumericCharactersAreNotPercentEscaped() {
    
        // Given
        let parameters = ["numbers": "0123456789"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "numbers=0123456789")
    }
    
    func testThatUnreservedLowercaseCharactersAreNotPercentEscaped() {
        // Given
        let parameters = ["lowercase": "abcdefghijklmnopqrstuvwxyz"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "lowercase=abcdefghijklmnopqrstuvwxyz")
    }
    
    func testThatUnreservedUppercaseCharactersAreNotPercentEscaped() {
        // Given
        let parameters = ["uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "uppercase=ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    }
    
    func testThatIllegalASCIICharactersArePercentEscaped() {
        // Given
        let parameters = ["illegal": " \"#%<>[]\\^`{}|"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        let expectedQuery = "illegal=%20%22%23%25%3C%3E%5B%5D%5C%5E%60%7B%7D%7C"
        XCTAssertEqual(result, expectedQuery)
    }
    
    // MARK: Tests - Special Character Queries
    
    func testURLParameterEncodeStringWithAmpersandKeyStringWithAmpersandValue() {
        // Given
        let parameters = ["foo&bar": "baz&qux", "foobar": "bazqux"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "foo%26bar=baz%26qux&foobar=bazqux")
    }
    
    func testURLParameterEncodeStringWithQuestionMarkKeyStringWithQuestionMarkValue() {
        // Given
        let parameters = ["?foo?": "?bar?"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "?foo?=?bar?")
    }
    
    func testURLParameterEncodeStringWithSlashKeyStringWithQuestionMarkValue() {
        // Given
        let parameters = ["foo": "/bar/baz/qux"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "foo=/bar/baz/qux")
    }
    
    func testURLParameterEncodeStringWithSpaceKeyStringWithSpaceValue() {
        // Given
        let parameters = [" foo ": " bar "]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "%20foo%20=%20bar%20")
    }
    
    func testURLParameterEncodeStringKeyPercentEncodedStringValue() {
        // Given
        let parameters = ["percent": "%25"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "percent=%2525")
    }
    
    func testURLEncodedParametersStringKeyNonLatinStringValue() {
        // Given
        let parameters = [
            "french": "français",
            "japanese": "日本語",
            "arabic": "العربية",
            "emoji": "😃"
        ]
        
        // When
        let result = urlEncode(from: parameters)
            
        // Then
        let expectedParameterValues = [
            "arabic=%D8%A7%D9%84%D8%B9%D8%B1%D8%A8%D9%8A%D8%A9",
            "emoji=%F0%9F%98%83",
            "french=fran%C3%A7ais",
            "japanese=%E6%97%A5%E6%9C%AC%E8%AA%9E"
        ]
            
        let expectedQuery = expectedParameterValues.joined(separator: "&")
        XCTAssertEqual(result, expectedQuery)
    }
    
    func testURLEncodedParametersWithString() {
        // Given
        let parameters = ["page": "0"]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "page=0")
    }
    
    func testURLEncodedParametersWithPlusKeyStringWithPlusValue() {
        // Given
        let parameters = ["+foo+": "+bar+"]
            
        // When
        let result = urlEncode(from: parameters)
            
        // Then
        XCTAssertEqual(result, "%2Bfoo%2B=%2Bbar%2B")
    }
    
    func testURLEncodedParametersWithChineseCharacters() {
        // Given
        let repeatedCount = 2_000
        let parameters = ["chinese": String(repeating: "一二三四五六七八九十", count: repeatedCount)]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        var expected = "chinese="
        
        for _ in 0..<repeatedCount {
            expected += "%E4%B8%80%E4%BA%8C%E4%B8%89%E5%9B%9B%E4%BA%94%E5%85%AD%E4%B8%83%E5%85%AB%E4%B9%9D%E5%8D%81"
        }
        
        XCTAssertEqual(result, expected)
    }
    
    func testURLEncodedParameters() {
        // Given
        let parameters = ["foo": 1, "bar": 2]
        
        // When
        let result = urlEncode(from: parameters)
        
        // Then
        XCTAssertEqual(result, "bar=2&foo=1")
    }
}
