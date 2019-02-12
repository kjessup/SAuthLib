//
//  OAuth.swift
//  SAuthLib
//
//  Created by Kyle Jessup on 2018-02-26.
//

import Foundation
import PerfectNIOCompat
import SAuthCodables

public enum OAuthProvider: String {
	case google = "google"
	case facebook = "facebook"
	case linkedin = "linkedin"
}

public struct OAuthProviderAndToken: Codable {
	let provider: String
	let token: String
}

public struct OAuthHandlers<S: SAuthConfigProvider> {
	let sauthDB: S
	public init(_ s: S) {
		sauthDB = s
	}
	
	public func oauthReturnHandler(request: HTTPRequest, response: HTTPResponse) {
		guard let uri = try? sauthDB.getURI(.oauthRedirect) else {
			return response.setBody(string: "URIs not configured.")
				.completed(status: .badRequest)
		}
		let provider = request.urlVariables["provider"] ?? ""
		let str = request.queryParams.map { "\($0.0.stringByEncodingURL)=\($0.1.stringByEncodingURL)" }.joined(separator: "&")
		let url = "\(uri)\(provider)/?\(str)"
		response.setHeader(.location, value: url)
			.completed(status: .temporaryRedirect)
	}
	
	public func oauthLoginHandler(request: HTTPRequest) throws -> TokenAcquiredResponse {
		let provTok: OAuthProviderAndToken = try request.decode()
		guard let provider = OAuthProvider(rawValue: provTok.provider) else {
			throw HTTPResponseError(status: .badRequest, description: "Bad provider.")
		}
		switch provider {
		case .google:
			guard let gInfo = getGooglePlusData(provTok.token),
				let address = gInfo.email else {
				throw HTTPResponseError(status: .badRequest, description: "Unable to get Google profile info.")
			}
			let meta = AccountPublicMeta(fullName: gInfo.displayName)
			let tokenResponse = try SAuth(self.sauthDB).createOrLogIn(provider: provTok.provider,
								accessToken: provTok.token,
								address: address,
								meta: meta)
			return tokenResponse
		case .facebook:
			guard let gInfo = getFacebookData(provTok.token) else {
				throw HTTPResponseError(status: .badRequest, description: "Unable to get Facebook profile info.")
			}
			let meta = AccountPublicMeta(fullName: gInfo.name)
			let tokenResponse = try SAuth(self.sauthDB).createOrLogIn(provider: provTok.provider,
																	  accessToken: provTok.token,
																	  address: gInfo.email,
																	  meta: meta)
			return tokenResponse
		case .linkedin:
			guard let gInfo = getLinkedInData(provTok.token) else {
				throw HTTPResponseError(status: .badRequest, description: "Unable to get LinkedIn profile info.")
			}
			let meta = AccountPublicMeta(fullName: "\(gInfo.firstName) \(gInfo.lastName)")
			let tokenResponse = try SAuth(self.sauthDB).createOrLogIn(provider: provTok.provider,
																	  accessToken: provTok.token,
																	  address: gInfo.emailAddress,
																	  meta: meta)
			return tokenResponse
		}
	}
}





