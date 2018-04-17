//
//  SAuthLib.swift
//  SAuthLib
//
//  Created by Kyle Jessup on 2018-02-26.
//

import Foundation
import PerfectHTTP
import PerfectCrypto
import PerfectCRUD
import PerfectNotifications
import PerfectMustache
import SAuthCodables

let passwordResetTokenExpirationIntervalSeconds = 15 * 60

public extension Date {
	var sauthTimeInterval: Int {
		return Int(timeIntervalSince1970)
	}
}

public struct AuthenticatedRequest {
	let request: HTTPRequest
	let token: String
	let account: Account
	let aliasId: String
}

public struct MobileDeviceId: Codable {
	let deviceId: String
	let deviceType: String
	let aliasId: String
	let createdAt: Int
}

public struct PasswordResetToken: Codable {
	let aliasId: String
	let authId: String
	let expiration: Int
}

public struct SAuthHandlers<S: SAuthConfigProvider> {
	let sauthDB: S
	public init(_ s: S) {
		sauthDB = s
	}
	public func register(request: HTTPRequest) throws -> TokenAcquiredResponse {
		let rrequest: AuthAPI.RegisterRequest = try request.decode()
		let tokenResponse = try SAuth(sauthDB).createAccount(address: rrequest.email, password: rrequest.password)
		return tokenResponse
	}
	public func login(request: HTTPRequest) throws -> TokenAcquiredResponse {
		let rrequest: AuthAPI.LoginRequest = try request.decode()
		let tokenResponse = try SAuth(sauthDB).logIn(address: rrequest.email, password: rrequest.password)
		let db = try sauthDB.getDB()
		let table = db.table(PasswordResetToken.self)
		try table.where(\PasswordResetToken.aliasId == rrequest.email.lowercased()).delete()
		return tokenResponse
	}
	public func authenticated(request: HTTPRequest) throws -> AuthenticatedRequest {
		guard let bearer = request.header(.authorization), !bearer.isEmpty else {
			throw HTTPResponseError(status: .unauthorized, description: "No authorization header provided.")
		}
		let prefix = "Bearer "
		let token: String
		if bearer.hasPrefix(prefix) {
			token = String(bearer[bearer.index(bearer.startIndex, offsetBy: prefix.count)...])
		} else {
			token = bearer
		}
		do {
			if let jwtVer = JWTVerifier(token) {
				try jwtVer.verify(algo: .rs256, key: sauthDB.getServerPublicKey())
				let payload = try jwtVer.decode(as: TokenClaim.self)
				if let accountId = payload.accountId,
					let alias = payload.subject {
					return AuthenticatedRequest(request: request,
												token: token,
												account: Account(id: accountId, flags: 0, createdAt: 0),
												aliasId: alias)
				}
			}
		} catch {}
		throw HTTPResponseError(status: .unauthorized, description: "Invalid authorization header provided.")
	}
	public func getMe(request: AuthenticatedRequest) throws -> Account {
		let account = try SAuth(sauthDB).getAccount(token: request.token)
		return account
	}
	public func getMeMeta(request: AuthenticatedRequest) throws -> AccountPublicMeta {
		guard let meta = try SAuth(sauthDB).getMeta(token: request.token) else {
			throw HTTPResponseError(status: .unauthorized, description: "Unable to fetch meta data.")
		}
		return meta
	}
	public func setMeMeta(request: AuthenticatedRequest) throws -> EmptyReply {
		let meta: AccountPublicMeta = try request.request.decode()
		try SAuth(sauthDB).setMeta(token: request.token, meta: meta)
		return EmptyReply()
	}
	public func addMobileDevice(request: AuthenticatedRequest) throws -> EmptyReply {
		let addReq: AuthAPI.AddMobileDeviceRequest = try request.request.decode()
		let deviceId = addReq.deviceId
		let db = try sauthDB.getDB()
		let add = MobileDeviceId(deviceId: deviceId,
								 deviceType: addReq.deviceType,
								 aliasId: request.aliasId,
								 createdAt: Date().sauthTimeInterval)
		do {
			_ = try db.table(MobileDeviceId.self).insert(add)
		} catch {
			// unique constraint conflict is expected here
		}
		return EmptyReply()
	}
}

extension SAuthHandlers {
	public func pwResetWeb(request: HTTPRequest, response: HTTPResponse) {
		guard let token = request.urlVariables["token"], !token.isEmpty else {
			return response.completed(status: .notFound)
		}
		guard let tempForm = try? sauthDB.getTemplatePath(.passwordResetForm),
			let tempErr = try? sauthDB.getTemplatePath(.passwordResetError) else {
				return response.setBody(string: "Templates not configured.").completed(status: .badRequest)
		}
		do {
			let db = try sauthDB.getDB()
			let table = db.table(PasswordResetToken.self)
			let whereToken = table.where(\PasswordResetToken.authId == token)
			let newToken = try db.transaction {
				() -> PasswordResetToken? in
				guard let resetToken = try whereToken.first() else {
					throw HTTPResponseError(status: .notFound, description: "Token not found.")
				}
				let addr = resetToken.aliasId
				guard resetToken.expiration > Date().sauthTimeInterval else {
					try table.where(\PasswordResetToken.aliasId == addr).delete()
					return nil
				}
				let newToken = try self.addPasswordResetToken(address: addr, db: db)
				return PasswordResetToken(aliasId: addr, authId: newToken, expiration: 0)
			}
			guard let newResetToken = newToken else {
				throw HTTPResponseError(status: .notFound, description: "Token not found.")
			}
			let dict: [String:Any] = ["token":newResetToken.authId, "address":newResetToken.aliasId]
			response.renderMustache(template: tempForm, context: dict)
		} catch {
			response.renderMustache(template: tempErr, context: ["error":error])
		}
	}
	public func pwResetWebComplete(request: HTTPRequest, response: HTTPResponse) {
		guard let tempOk = try? sauthDB.getTemplatePath(.passwordResetOk),
			let tempErr = try? sauthDB.getTemplatePath(.passwordResetError) else {
				return response.setBody(string: "Templates not configured.").completed(status: .badRequest)
		}
		do {
			_ = try completePasswordReset(request: request)
			response.renderMustache(template: tempOk)
		} catch {
			response.renderMustache(template: tempErr, context: ["error":error])
		}
	}
}

extension SAuthHandlers {
	private func addPasswordResetToken(address loweredAddress: String, db: Database<S.DBConfig>) throws -> String {
		let authId = UUID().uuidString
		let table = db.table(PasswordResetToken.self)
		try table.where(\PasswordResetToken.aliasId == loweredAddress).delete()
		let exp = Date().sauthTimeInterval + passwordResetTokenExpirationIntervalSeconds
		let token = PasswordResetToken(aliasId: loweredAddress, authId: authId, expiration: exp)
		try table.insert(token)
		return authId
	}
	
	public func initiatePasswordReset(request: HTTPRequest) throws -> EmptyReply {
		let resetRequest: AuthAPI.PasswordResetRequest = try request.decode()
		let loweredAddress = resetRequest.address.lowercased()
		let db = try sauthDB.getDB()
		guard let alias = try db.table(AliasBrief.self).where(\AliasBrief.address == loweredAddress).first() else {
			throw HTTPResponseError(status: .badRequest, description: "Bad account alias.")
		}
		let authId = try db.transaction {
			return try addPasswordResetToken(address: loweredAddress, db: db)
		}
		let deviceTable = db.table(MobileDeviceId.self)
		if let deviceId = resetRequest.deviceId,
			try deviceTable
			.where(\MobileDeviceId.aliasId == loweredAddress &&
				\MobileDeviceId.deviceType == "ios" &&
				\MobileDeviceId.deviceId == deviceId).count() == 1 {
			let n = NotificationPusher(apnsTopic: try sauthDB.getPushConfigurationTopic(forType: "ios"))
			n.pushAPNS(
				configurationName: try sauthDB.getPushConfigurationName(forType: "ios"),
				deviceTokens: [deviceId],
				notificationItems: [.customPayload("auth", authId), .alertBody("password reset")]) {
					responses in
					guard let f = responses.first else {
						return
					}
					if case .ok = f.status {
						// !FIX! wait N minutes and if the token is still there send an email?
						return
					} else {
						_ = try? self.sendEmailPasswordReset(address: loweredAddress, authId: authId, alias: alias, db: db)
					}
			}
			return EmptyReply()
		}
		return try sendEmailPasswordReset(address: loweredAddress, authId: authId, alias: alias, db: db)
	}
	
	private func sendEmailPasswordReset(address loweredAddress: String,
										authId: String,
										alias: AliasBrief,
										db: Database<S.DBConfig>) throws -> EmptyReply {
		guard let account = try db.table(Account.self).where(\Account.id == alias.account).first() else {
			throw HTTPResponseError(status: .badRequest, description: "Bad account.")
		}
		try sauthDB.sendEmailPasswordReset(authToken: authId,
										   account: account,
										   alias: alias)
		return EmptyReply()
	}
	
	public func completePasswordReset(request: HTTPRequest) throws -> TokenAcquiredResponse {
		let resetRequest: AuthAPI.PasswordResetCompleteRequest = try request.decode()
		let loweredAddress = resetRequest.address.lowercased()
		do {
			let db = try sauthDB.getDB()
			try db.transaction {
				guard try db.table(Alias.self).where(\Alias.address == loweredAddress).count() == 1 else {
					throw HTTPResponseError(status: .badRequest, description: "Bad account alias.")
				}
				let table = db.table(PasswordResetToken.self)
				guard try table.where(\PasswordResetToken.aliasId == loweredAddress &&
					\PasswordResetToken.authId == resetRequest.authToken &&
					\PasswordResetToken.expiration > Date().sauthTimeInterval).count() == 1 else {
						throw HTTPResponseError(status: .badRequest, description: "Bad password reset token.")
				}
				try table.where(\PasswordResetToken.aliasId == loweredAddress).delete()
			}
		}
		return try SAuth(sauthDB).changePasswordUnchecked(address: loweredAddress, password: resetRequest.password)
	}
}

extension SAuthHandlers {
	public func validateAlias(request: HTTPRequest, response: HTTPResponse) {
		
	}
}
