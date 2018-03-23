//
//  GoogleOAuth2.swift
//  SAuthLib
//
//  Created by Kyle Jessup on 2018-02-26.
//

import Foundation
import PerfectCURL

struct GooglePlusName: Codable {
	let givenName: String?
	let familyName: String?
}

struct GooglePlusEmail: Codable {
	let type: String
	let value: String
}

struct GooglePlusImage: Codable {
	let url: String
	let isDefault: Bool
}

struct GoogleProfileInfo: Codable {
	let name: GooglePlusName?
	let emails: [GooglePlusEmail]?
	let id: String
	let image: GooglePlusImage?
	let displayName: String?
	
	var email: String? {
		guard let emails = self.emails else {
			return nil
		}
		guard let email = emails.first(where: { $0.type == "account" }) ?? emails.first else {
			return nil
		}
		return email.value
	}
}

/// After exchanging token, this function retrieves user information from Google
func getGooglePlusData(_ accessToken: String) -> GoogleProfileInfo? {
	let url = "https://www.googleapis.com/plus/v1/people/me"
	let request = CURLRequest(url, .addHeader(.authorization, "Bearer \(accessToken)"))
	return try? request.perform().bodyJSON(GoogleProfileInfo.self)
}
