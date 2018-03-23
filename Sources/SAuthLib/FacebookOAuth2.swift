//
//  FacebookOAuth2.swift
//  SAuthLib
//
//  Created by Kyle Jessup on 2018-03-01.
//

import Foundation
import PerfectCURL

struct FacebookProfileInfo: Codable {
	let name: String
	let email: String
	let id: String
	let image: FacebookProfileImage?
	var imageUrl: String? { return image?.picture?.url }
}

struct FacebookProfileImage: Codable {
	struct FacebookProfileImage: Codable {
		let height: Int
		let width: Int
		let url: String
	}
	let picture: FacebookProfileImage?
}

// "picture\":{\"data\":{\"height\":50,\"is_silhouette\":true,\"url\":\"https:\\/\\/scontent.xx.fbcdn.net\\/v\\/t1.0-1\\/c15.0.50.50\\/p50x50\\/10354686_10150004552801856_220367501106153455_n.jpg?oh=58094ae96718bcfcbd53cfea5151eaf5&oe=5B137D2F\",\"width\":50}

/// After exchanging token, this function retrieves user information from Facebook
func getFacebookData(_ accessToken: String) -> FacebookProfileInfo? {
	let url = "https://graph.facebook.com/v2.8/me?fields=name,email,picture&access_token=\(accessToken)"
	let request = CURLRequest(url)
	return try? request.perform().bodyJSON(FacebookProfileInfo.self)
}
