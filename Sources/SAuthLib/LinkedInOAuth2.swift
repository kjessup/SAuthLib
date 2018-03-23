//
//  LinkedInOAuth2.swift
//  SAuthLib
//
//  Created by Kyle Jessup on 2018-03-06.
//

import Foundation
import PerfectCURL

struct LinkedInProfileInfo: Codable {
	let id: String
	let firstName: String
	let lastName: String
	let emailAddress: String
	let pictureUrl: String
}

func getLinkedInData(_ accessToken: String) -> LinkedInProfileInfo? {
	let url = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,picture-url,email-address)?format=json"
	let request = CURLRequest(url, .addHeader(.authorization, "Bearer \(accessToken)"))
	return try? request.perform().bodyJSON(LinkedInProfileInfo.self)
}
