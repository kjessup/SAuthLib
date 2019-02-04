//
//  SAuth.swift
//  SAuthLib
//
//  Created by Kyle Jessup on 2018-02-26.
//

import Foundation
import PerfectCRUD
import PerfectCrypto
import SAuthCodables

public enum AliasFlags: UInt {
	case provisional = 0x01
	case inprogress = 0x02
}

extension Alias {
	var provisional: Bool {
		return 0 != (flags & AliasFlags.provisional.rawValue)
	}
}

extension AliasBrief: TableNameProvider {
	public static var tableName = Alias.CRUDTableName
	var provisional: Bool {
		return 0 != (flags & AliasFlags.provisional.rawValue)
	}
}

let tokenExpirationSeconds = 31536000
let encryptCipher = Cipher.aes_256_cbc
let jwtAlgo = JWT.Alg.rs256
let digestAlgo = Digest.sha256

public enum TemplateKey {
	case passwordResetForm, passwordResetOk, passwordResetError, passwordResetEmail
	case accountValidationEmail, accountValidationError, accountValidationOk
}

public enum URIKey {
	case oauthRedirect, passwordReset, accountValidate
}

public protocol SAuthConfigProvider {
	associatedtype DBConfig: DatabaseConfigurationProtocol
	func getDB() throws -> Database<DBConfig>
	
	func getServerPublicKey() throws -> PEMKey
	func getServerPrivateKey() throws -> PEMKey
	
	func getPushConfigurationName(forType: String) throws -> String
	func getPushConfigurationTopic(forType: String) throws -> String
	
	// authToken will be URI-safe
	func sendEmailPasswordReset(authToken: String, account: Account, alias: AliasBrief) throws
	func sendEmailValidation(authToken: String, account: Account, alias: AliasBrief) throws
	
	func getTemplatePath(_ key: TemplateKey) throws -> String
	func getURI(_ key: URIKey) throws -> String
}

public struct SAuth<P: SAuthConfigProvider> {
	let provider: P
	public typealias DB = Database<P.DBConfig>
	private func getDB() throws -> DB {
		return try provider.getDB()
	}
	public init(_ p: P) {
		provider = p
	}
	public func initialize() throws {
		_ = PerfectCrypto.isInitialized
		let db = try getDB()
		try db.create(Account.self, primaryKey: \.id, policy: .reconcileTable)
		try db.create(Alias.self, policy: .reconcileTable).index(unique: true, \.address)
		try db.create(AccessToken.self, policy: .reconcileTable).index(unique: true, \.provider, \.token, \.aliasId)
		try db.create(MobileDeviceId.self, policy: .reconcileTable).index(unique: true, \.deviceId, \.aliasId)
		try db.create(PasswordResetToken.self, primaryKey: \.aliasId, policy: .reconcileTable)
		try db.create(AccountValidationToken.self, primaryKey: \.aliasId, policy: .reconcileTable)
		try db.create(Audit.self, policy: .reconcileTable)
	}
	private func pwHash(password: String) -> (hexSalt: String, hexHash: String)? {
		let saltBytes = Array<UInt8>(randomCount: 32)
		guard let saltHex = saltBytes.encode(.hex),
			let hashHex = pwHash(password: password, saltBytes: saltBytes) else {
				return nil
		}
		return (String(validatingUTF8: saltHex) ?? "", hashHex)
	}
	private func pwHash(password: String, saltBytes: [UInt8]) -> String? {
		let pwBytes = Array(password.utf8)
		guard let hashBytes = digestAlgo.deriveKey(password: pwBytes, salt: saltBytes, iterations: 2048, keyLength: 32),
			let hashHex = hashBytes.encode(.hex) else {
				return nil
		}
		return String(validatingUTF8: hashHex) ?? ""
	}
	private func pwValidate(password: String, hexSalt: String, hexHash: String) -> Bool {
		guard let saltBytes = hexSalt.decode(.hex),
			let compareHexHash = pwHash(password: password, saltBytes: saltBytes) else {
				return false
		}
		return compareHexHash == hexHash		
	}
	private func newClaim(_ address: String,
						  accoundId: UUID?,
						  oauthProvider: String? = nil,
						  oauthAccessToken: String? = nil) -> TokenClaim {
		let now = Date().sauthTimeInterval
		return TokenClaim(issuer: "sauth",
						   subject: address,
						   expiration: now + tokenExpirationSeconds,
						   issuedAt: now,
						   accountId: accoundId,
						   oauthProvider: oauthProvider,
						   oauthAccessToken: oauthAccessToken)
	}
	
	// create account
	public func createAccount(address: String, password: String, fullName: String?) throws -> (Account, Alias) {
		let db = try getDB()
		let loweredAddress = address.lowercased()
		let now = Date().sauthTimeInterval
		let table = db.table(Alias.self)
		let whereMatch = table.where(\Alias.address == loweredAddress)
		let id = UUID()
		guard let (salt, hash) = pwHash(password: password) else {
			try badAudit(db: db, alias: loweredAddress, action: "create account", error: "Failure hashing password.")
		}
		let ret: (Account, Alias)? = try db.transaction {
			let existingCount = try whereMatch.count()
			guard existingCount == 0 else {
				return nil
			}
			let meta = AccountPublicMeta(fullName: fullName)
			let account = Account(id: id, flags: 0, createdAt: now, meta: meta)
			try db.table(Account.self).insert(account)
			let alias = Alias(address: loweredAddress,
							  account: id,
							  priority: 1,
							  flags: AliasFlags.provisional.rawValue,
							  pwSalt: salt, pwHash: hash,
							  defaultLocale: nil)
			try table.insert(alias)
			goodAudit(db: db, alias: loweredAddress, action: "create account", account: account.id)
			return (account, alias)
		}
		guard let r = ret else {
			try badAudit(db: db, alias: loweredAddress, action: "create account", error: "Alias already exists.")
		}
		return r
	}

	// log in to account
	public func logIn(address: String, password: String) throws -> TokenAcquiredResponse {
		let loweredAddress = address.lowercased()
		let db = try getDB()
		let table = db.table(Alias.self)
		guard let alias = try table.where(\Alias.address == loweredAddress).first() else {
			try badAudit(db: db, alias: loweredAddress, action: "login", error: "Bad alias.")
		}
		guard !alias.provisional else {
			try badAudit(db: db, alias: loweredAddress, action: "login", error: "This alias has not been validated.")
		}
		guard let hash = alias.pwHash, let salt = alias.pwSalt else {
			try badAudit(db: db, alias: loweredAddress, action: "login", error: "This alias does not have a password.")
		}
		guard pwValidate(password: password, hexSalt: salt, hexHash: hash) else {
			try badAudit(db: db, alias: loweredAddress, action: "login", error: "Bad password.")
		}
		let account = try db.table(Account.self).where(\Account.id == alias.account).first()
		let privateKey = try provider.getServerPrivateKey()
		let claim = newClaim(loweredAddress, accoundId: account?.id)
		let token = try JWTCreator(payload: claim).sign(alg: jwtAlgo, key: privateKey)
		goodAudit(db: db, alias: loweredAddress, action: "login", account: account?.id)
		return TokenAcquiredResponse(token: token, account: account)
	}
	
	// change password. no permissions checking done here
	public func changePasswordUnchecked(address: String, password: String) throws -> TokenAcquiredResponse {
		let db = try getDB()
		let loweredAddress = address.lowercased()
		let table = db.table(Alias.self)
		let whereMatch = table.where(\Alias.address == loweredAddress)
		guard let (salt, hash) = pwHash(password: password) else {
			try badAudit(db: db, alias: loweredAddress, action: "change password", error: "Failure hashing password.")
		}
		guard let foundAlias = try whereMatch.first() else {
			try badAudit(db: db, alias: loweredAddress, action: "change password", error: "Bad account alias.")
		}
		let alias: Alias = try db.transaction {
			let updated = Alias(address: foundAlias.address,
							  account: foundAlias.account,
							  priority: foundAlias.priority,
							  flags: foundAlias.flags,
							  pwSalt: salt, pwHash: hash,
							  defaultLocale: nil)
			try whereMatch.update(updated, setKeys: \Alias.pwSalt, \Alias.pwHash)
			return updated
		}
		guard !alias.provisional else {
			try badAudit(db: db, alias: loweredAddress, action: "change password", error: "This alias has not been validated.")
		}
		let account = try db.table(Account.self).where(\Account.id == alias.account).first()
		let privateKey = try provider.getServerPrivateKey()
		let claim = newClaim(loweredAddress, accoundId: account?.id)
		let token = try JWTCreator(payload: claim).sign(alg: jwtAlgo, key: privateKey)
		goodAudit(db: db, alias: loweredAddress, action: "change password", account: account?.id)
		return TokenAcquiredResponse(token: token, account: account)
	}
	
	// validate token
	private func validateToken(_ token: String, db: DB) throws -> Alias {
		guard let valid = JWTVerifier(token) else {
			throw SAuthError(description: "Bad token.")
		}
		let claim = try valid.decode(as: TokenClaim.self)
		guard let id = claim.subject,
			let exp = claim.expiration else {
				throw SAuthError(description: "Bad token. No subject or expiration.")
		}
		let table = db.table(Alias.self)
		guard let alias = try table.where(\Alias.address == id).first() else {
			try badAudit(db: db, alias: id, action: "validate token", error: "Bad alias.")
		}
		let publicKey = try provider.getServerPublicKey()
		try valid.verify(algo: jwtAlgo, key: publicKey)
		guard exp >= Date().sauthTimeInterval else {
			try badAudit(db: db, alias: id, action: "validate token", error: "Token expired.")
		}
		// no good audit for this
		return alias
	}
	
	// validate token
	public func validateToken(_ token: String) throws -> Alias {
		return try validateToken(token, db: getDB())
	}
	
	// add alias to account (additional un/pw)
	public func addAlias(token: String, address: String, password: String) throws -> TokenAcquiredResponse {
		let db = try getDB()
		let existing = try validateToken(token, db: db)
		return try addAlias(accountId: existing.account, address: address, password: password, db: db)
	}
	
	private func addAlias(accountId: UUID, address: String, password: String, db: DB) throws -> TokenAcquiredResponse {
		let loweredAddress = address.lowercased()
		let table = db.table(Alias.self)
		let whereMatch = table.where(\Alias.address == loweredAddress)
		guard let (salt, hash) = pwHash(password: password) else {
			try badAudit(db: db, alias: loweredAddress, action: "add alias", error: "Failure hashing password.")
		}
		var doBadAudit = false
		try db.transaction {
			let existingCount = try whereMatch.count()
			guard existingCount == 0 else {
				doBadAudit = true
				return
			}
			let alias = Alias(address: loweredAddress,
							  account: accountId,
							  priority: 0,
							  flags: AliasFlags.provisional.rawValue,
							  pwSalt: salt, pwHash: hash,
							  defaultLocale: nil)
			try table.insert(alias)
		}
		if doBadAudit {
			try badAudit(db: db, alias: loweredAddress, action: "add alias", error: "Alias already exists.")
		}
		let account = try db.table(Account.self).where(\Account.id == accountId).first()
		let privateKey = try provider.getServerPrivateKey()
		let claim = newClaim(loweredAddress, accoundId: account?.id)
		let token = try JWTCreator(payload: claim).sign(alg: jwtAlgo, key: privateKey)
		goodAudit(db: db, alias: loweredAddress, action: "add alias", account: account?.id)
		return TokenAcquiredResponse(token: token, account: account)
	}

	// unassociate alias from account
	public func removeAlias(token: String, address: String) throws {
		let loweredAddress = address.lowercased()
		let db = try getDB()
		let existing = try validateToken(token, db: db)
		let table = db.table(Alias.self)
		try table
			.where(\Alias.address == loweredAddress && \Alias.account == existing.account)
			.delete()
		goodAudit(db: db, alias: loweredAddress, action: "remove alias", account: existing.account)
	}
	
	// list account aliases
	public func listAliases(token: String) throws -> [AliasBrief] {
		let db = try getDB()
		let existing = try validateToken(token, db: db)
		let table = db.table(AliasBrief.self)
		// no audit
		return try table
			.where(\AliasBrief.account == existing.account)
			.select().map { $0 }
	}

	// get meta data for account
	public func getMeta(token: String, for: UUID) throws -> AccountPublicMeta? {
		let db = try getDB()
		_ = try validateToken(token, db: db)
		let account = try db.table(Account.self)
			.where(\Account.id == `for`)
			.first()
		// no audit
		return account?.meta
	}
	
	// get meta data for account
	public func getMeta(token: String) throws -> AccountPublicMeta? {
		let db = try getDB()
		let me = try validateToken(token, db: db)
		let account = try db.table(Account.self)
			.where(\Account.id == me.account)
			.first()
		// no audit
		return account?.meta
	}
	
	// add meta data to account
	public func setMeta(token: String, meta: AccountPublicMeta) throws {
		let db = try getDB()
		let id = try validateToken(token, db: db).account
		let newAcc = Account(id: id, flags: 0, createdAt: 0, meta: meta)
		try db.table(Account.self)
			.where(\Account.id == id)
			.update(newAcc, setKeys: \.meta)
		goodAudit(db: db, alias: "*", action: "set meta", account: id)
	}
	
	public func createOrLogIn(provider: String,
							  accessToken: String,
							  address: String,
							  meta: AccountPublicMeta) throws -> TokenAcquiredResponse {
		let loweredAddress = address.lowercased()
		let db = try getDB()
		let table = db.table(Alias.self)
		if try table.where(\Alias.address == loweredAddress).count() == 1 {
			let response = try logIn(provider: provider, accessToken: accessToken, address: address, db: db)
			try setMeta(token: response.token, meta: meta)
			return response
		}
		return try createAccount(provider: provider, accessToken: accessToken, address: address, meta: meta, db: db)
	}
	
	// receive OAuth token and create new account
	public func createAccount(provider: String,
							  accessToken: String,
							  address: String,
							  meta: AccountPublicMeta) throws -> TokenAcquiredResponse {
		let db = try getDB()
		return try createAccount(provider: provider, accessToken: accessToken, address: address, meta: meta, db: db)
	}
	
	func createAccount(provider: String,
					  accessToken: String,
					  address: String,
					  meta: AccountPublicMeta,
					  db: DB) throws -> TokenAcquiredResponse {
		let loweredAddress = address.lowercased()
		let now = Date().sauthTimeInterval
		let table = db.table(Alias.self)
		let id = UUID()
		var account: Account?
		var doBadAudit = false
		try db.transaction {
			let existingCount = try table.where(\Alias.address == loweredAddress).count()
			guard existingCount == 0 else {
				doBadAudit = true
				return
			}
			let acc = Account(id: id, flags: 0, createdAt: now, meta: meta)
			account = acc
			try db.table(Account.self).insert(acc)
			let alias = Alias(address: loweredAddress,
							  account: id,
							  priority: 1,
							  flags: 0,
							  pwSalt: nil, pwHash: nil,
							  defaultLocale: nil)
			try table.insert(alias)
		}
		if doBadAudit {
			try badAudit(db: db, alias: loweredAddress, action: "create account", provider: provider, error: "Alias already exists.")
		}
		let tokensTable = db.table(AccessToken.self)
		try db.transaction {
			let token = AccessToken(aliasId: loweredAddress,
									provider: provider,
									token: accessToken,
									expiration: nil)
			try tokensTable.insert(token)
		}
		let privateKey = try self.provider.getServerPrivateKey()
		let claim = newClaim(loweredAddress, accoundId: account?.id, oauthProvider: provider, oauthAccessToken: accessToken)
		let token = try JWTCreator(payload: claim).sign(alg: jwtAlgo, key: privateKey)
		goodAudit(db: db, alias: loweredAddress, action: "create account", account: account?.id, provider: provider)
		return TokenAcquiredResponse(token: token, account: account)
	}
	
	// receive OAuth token and log in to existing account
	public func logIn(provider: String,
					  accessToken: String,
					  address: String) throws -> TokenAcquiredResponse {
		let db = try getDB()
		return try logIn(provider: provider, accessToken: accessToken, address: address, db: db)
	}
	
	func logIn(provider: String,
			   accessToken: String,
			   address: String,
			   db: DB) throws -> TokenAcquiredResponse {
		let loweredAddress = address.lowercased()
		let db = try getDB()
		let table = db.table(Alias.self)
		guard let alias = try table.where(\Alias.address == loweredAddress).first() else {
			try badAudit(db: db, alias: loweredAddress, action: "login", error: "Bad account alias.")
		}
		guard !alias.provisional else {
			try badAudit(db: db, alias: loweredAddress, action: "login", error: "This alias has not been validated.")
		}
		let tokensTable = db.table(AccessToken.self)
		try db.transaction {
			let whereMatch = tokensTable
				.where(\AccessToken.aliasId == loweredAddress &&
					\AccessToken.provider == provider &&
					\AccessToken.token == accessToken)
			let token = AccessToken(aliasId: loweredAddress,
									provider: provider,
									token: accessToken,
									expiration: nil)
			if try whereMatch.count() == 1 {
//				try whereMatch.update(token, setKeys: \.expiration)
			} else {
				try tokensTable.insert(token)
			}
		}
		let account = try db.table(Account.self).where(\Account.id == alias.account).first()
		let privateKey = try self.provider.getServerPrivateKey()
		let claim = newClaim(loweredAddress, accoundId: account?.id, oauthProvider: provider, oauthAccessToken: accessToken)
		let token = try JWTCreator(payload: claim).sign(alg: jwtAlgo, key: privateKey)
		goodAudit(db: db, alias: loweredAddress, action: "login", account: account?.id)
		return TokenAcquiredResponse(token: token, account: account)
	}
	
	public func getAccount(token: String) throws -> Account {
		let val = try validateToken(token)
		let db = try getDB()
		let table = db.table(Account.self)
		guard let account = try table.where(\Account.id == val.account).first() else {
			try badAudit(db: db, alias: val.address, action: "get account", account: val.account, error: "Bad account.")
		}
		// no audit
		return account
	}
	
	public func goodAudit(db: DB,
			   alias: String,
			   action: String,
			   account: UUID? = nil,
			   provider: String? = nil) {
		let audit = Audit(alias: alias,
						  action: action,
						  account: account,
						  provider: provider,
						  error: nil,
						  attemptedAt: Date().sauthTimeInterval)
		_ = try? db.table(Audit.self).insert(audit)
	}
	
	public func badAudit(db: DB,
			   alias: String,
			   action: String,
			   account: UUID? = nil,
			   provider: String? = nil,
			   error: String) throws -> Never {
		let audit = Audit(alias: alias,
						  action: action,
						  account: account,
						  provider: provider,
						  error: error,
						  attemptedAt: Date().sauthTimeInterval)
		try db.table(Audit.self).insert(audit)
		throw SAuthError(description: error)
	}
}


