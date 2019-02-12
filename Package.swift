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
		.package(url: "https://github.com/PerfectlySoft/Perfect-CRUD.git", from: "1.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-NIOCompat.git", .branch("master")),
		.package(url: "https://github.com/PerfectlySoft/Perfect-Notifications.git", from: "4.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-CURL.git", from: "4.0.0"),
		.package(url: "https://github.com/PerfectlySoft/Perfect-SMTP.git", from: "4.0.0"),
	],
	targets: [
		.target(name: "SAuthLib", dependencies: ["SAuthCodables",
												 "PerfectSMTP",
												 "PerfectNIOCompat",
												 "PerfectCURL",
												 "PerfectCRUD",
												 "PerfectNotifications"])
	]
)
