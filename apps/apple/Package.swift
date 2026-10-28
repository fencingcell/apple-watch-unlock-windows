// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "WatchLoginCore", platforms: [.macOS(.v13)], products: [.library(name: "WatchLoginCore", targets: ["WatchLoginCore"])], targets: [.target(name: "WatchLoginCore", path: "Shared"), .testTarget(name: "WatchLoginCoreTests", dependencies: ["WatchLoginCore"], path: "Tests", exclude: ["test_package.py"])])
