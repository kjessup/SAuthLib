// swift-tools-version:4.0
// Generated automatically by Perfect Assistant 2
// Date: 2018-03-02 17:48:07 +0000
import PackageDescription

let package = Package(
	name: "SAuthLib",
	products: [
		.library(name: "SAuthLib", targets: ["SAuthLib"])
	],
	dependencies: [
		.package(url: "https://github.com/kjessup/SAuthCodables.git", .branch("master")),
		.package(url: "https://github.com/PerfectlySoft/Perfect-CRUD.git", .branch("master")),
		.package(url: "https://github.com/PerfectlySoft/Perfect-HTTP.git", from: "3.0.12"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-Notifications.git", from: "3.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-CURL.git", from: "3.0.6"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-SMTP.git", from: "3.2.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-Mustache.git", from: "3.0.0")
	],
	targets: [
		.target(name: "SAuthLib", dependencies: ["SAuthCodables", "PerfectMustache", "PerfectSMTP", "PerfectCURL", "PerfectHTTP", "PerfectCRUD", "PerfectNotifications"])
	]
)
