# IBM Verify Core SDK for iOS

The Core software development kit (SDK) provides common functionality across the other components in the IBM Verify SDK offering.  The core component will evolve over time and currently offers extensions and helpers for `URLSession` and the Keychain.

## Getting started

### Installation

[Swift Package Manager](https://swift.org/package-manager/) is used for automating the distribution of Swift code and is integrated into the `swift` compiler.  To depend on one or more of the components, you need to declare a dependency in your `Package.swift`:

```swift
dependencies: [
    .package(name: "IBM Verify", url: "https://github.com/ibm-verify/verify-sdk-ios.git", from: "3.0.12")
]
```

then in the `targets` section of the application/library, add one or more components to your `dependencies`, for example:

```swift
// Target for Swift 6.0
.target(name: "MyExampleApp", dependencies: [
    .product(name: "Core", package: "IBM Verify")
],
```

Alternatively, you can add the package manually.
1. Select your application project in the **Project Navigator** to display the configuration window.
2. Select your application project under the **PROJECT** heading
3. Select the **Swift Packages** tab.
4. Click on the `+` button.
5. Enter `https://github.com/ibm-verify/verify-sdk-ios.git` as the respository URL and follow the remaining steps selecting the components to add to your project.

### API documentation
The Core SDK API can be reviewed [here](https://ibm-verify.github.io/ios/documentation/core/).

### Importing the SDK

Add the following import statement to the `.swift` files you want to reference the Core SDK.

```swift
import Core
```

## Usage

### Interacting with the Keychain

Perform an add operation against the Keychain.  The `addItem` works with native types, such as `Date` and `Double`.
```swift
do {
   try KeychainService.default.addItem("createdDate", value: Date())
}
catch let error {
   print(error.localizedDescription)
}
```

You can add custom types that support `Codable` to the Keychain.
```swift

// Create a struct supporting Codable.
struct Person: Codable {
   var name: String
   var age: Int
}

let person = Person(name: "John Doe", age: 42)

do {
   try KeychainService.default.addItem("account", value: person)
}
catch let error {
   print(error.localizedDescription)
}
```

Read a `Codable` item from the Keychain.

```swift
guard let person = try? KeychainService.default.readItem("account", typeof: Person.self) {
    return
}
   
print(person))
```

Perform an delete operation against the Keychain.

```swift
try KeychainService.default.deleteItem("createdDate")
```

Rename an item in the Keychain.
```swift
do {
   try KeychainService.default.addItem("greeting", value: "Hello World")
   try KeychainService.default.renameItem("greeting", newKey: "welcome")
}
catch let error {
   print(error.localizedDescription)
}
```

Check if an item exists in the Keychain.
```swift
if let result = KeychainService.default.itemExists("greeting") {
   print(result)
}
```

Read and write a private key to the Keychain.
```swift
do {
   // Generate the private key.
   let privateKey = RSA.Signing.PrivateKey()   // Default 2048 in size and type is RSA

   // `accessControl: .userPresence` uses device PIN code as a biometric fallback when reading the item.
   try KeychainService.default.addItem("my_key_label", value: .key(value: privateKey.derRepresentation), accessControl: .userPresence)

   // Retrieve the private key data.
   let data = try KeychainService.default.readItem(name, searchType: .key)
   let privateKey2 = try RSA.Signing.PrivateKey(derRepresentation: data)
}
catch let error {
   print(error.localizedDescription)
}
```

### Making network requests

By extending `URLSession` you control the session configuration and how the data is parsed.

A simply JSON GET request
```swift
struct Post: Codable {
   var userId: Int
   var id: Int
   var title: String
   var body: String
}

let url = URL(string: "https://jsonplaceholder.typicode.com/posts")!
let resource = HttpResource<[Post]>(json: .get, url: url)
        
try await URLSession.shared.dataTask(for: resource) { result in
   switch result {
      case .success(let value):
         print(value)
      case .failure(let error):
         print(error.localizedDescription)
   }
}
```

Appendinng a query string parameters to a request.
```swift
struct Post: Codable {
   var userId: Int
   var id: Int
   var title: String
   var body: String
}

let url = URL(string: "https://jsonplaceholder.typicode.com/posts")!
let resource = HttpResource<[Post]>(json: .get, url: url, queryParams: ["userId": "1"])
        
try await URLSession.shared.dataTask(for: resource) { result in
   switch result {
      case .success(let value):
         print(value)
      case .failure(let error):
         print(error.localizedDescription)
    }
}
```

Custom parsing the JSON response.
```swift
let url = URL(string: "https://jsonplaceholder.typicode.com/posts")!
let request = URLRequest(url: url)
let resource = HttpResource<[Post]>(request: request, parse: { data, response in
   do {
      let value = try JSONDecoder().decode([Post].self, from: data!)
      return Result.success(value)
   }
   catch let error {
      return Result.failure(error)
   }
})

try await URLSession.shared.dataTask(for: resource) { result in
   switch result {
      case .success(let value):
         print(value)
      case .failure(let error):
         print(error.localizedDescription)
    }
}
```

Custom parsing of data, for example a `UIImage`.
```swift
let url = URL(string: "https://picsum.photos/id/0/5616/3744")!
let resource = HttpResource<UIImage>(.get, url: url, accept: .jpeg) { data, response in
   return Result {
      guard let data = data, let image = UIImage(data: data) else {
         throw URLSessionError.noData
      }
      
      return image
   }
}
        
try await URLSession.shared.dataTask(for: resource) { result in
   switch result {
   case .success(let image):
      // Do something with the image.
   case .failure(let error):
      print(error.localizedDescription)
   }
}
```

Perform a `map` operation over an array of items using a filter.
```swift
let url = URL(string: "https://jsonplaceholder.typicode.com/posts")!
let posts = HttpResource<[Post]>(json: .get, url: url)
let firstPost = posts.map{ $0.first }
        
try await URLSession.shared.dataTask(for: firstPost) { result in
   switch result {
      case .success(let value):
         print(value)
      case .failure(let error):
         print(error.localizedDescription)
    }
}
```

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
