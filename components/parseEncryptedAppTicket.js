const StdLib = require('@doctormckay/stdlib');
const SteamCrypto = require('@doctormckay/steam-crypto');

const Protos = require('../protobufs/generated/_load');
const parseAppTicket = require('./parseAppTicket');

module.exports = parseEncryptedAppTicket;

/**
 *
 * @param {Buffer} ticket - The raw encrypted appticket
 * @param {Buffer|string} encryptionKey - The app's encryption key, either raw hex or a Buffer
 * @returns {object}
 */
function parseEncryptedAppTicket(ticket, encryptionKey) {
	try {
		let outer = Protos.EncryptedAppTicket.decode(ticket);
		let key = typeof encryptionKey === 'string' ? Buffer.from(encryptionKey, 'hex') : encryptionKey;
		let decrypted = SteamCrypto.symmetricDecrypt(outer.encrypted_ticket, key);

		if (StdLib.Hashing.crc32(decrypted) != outer.crc_encryptedticket) {
			return null;
		}

		// the beginning is the user-supplied data
		let userData = decrypted.slice(0, outer.cb_encrypteduserdata);
		let ownershipTicketLength = decrypted.readUInt32LE(outer.cb_encrypteduserdata);
		let ownershipTicket = parseAppTicket(decrypted.slice(outer.cb_encrypteduserdata, outer.cb_encrypteduserdata + ownershipTicketLength), true);
		if (ownershipTicket) {
			ownershipTicket.userData = userData;
		}

		let remainder = decrypted.slice(outer.cb_encrypteduserdata + ownershipTicketLength);
		if (remainder.length >= 8 + 20) {
			// salted sha1 hash
			let dataToHash = decrypted.slice(0, outer.cb_encrypteduserdata + ownershipTicketLength);
			let salt = remainder.slice(0, 8);
			let hash = remainder.slice(8, 28);
			remainder = remainder.slice(28);

			if (!hash.equals(StdLib.Hashing.sha1(Buffer.concat([dataToHash, salt]), 'buffer'))) {
				return null;
			}

			if (ownershipTicket) {
				ownershipTicket.unknown1 = remainder.readUInt32LE(0);
			}
		}

		[
			'ownershipTicketExpires',
			'isExpired',
			'hasValidSignature',
			'isValid',
			'unknown1'
		].forEach((key) => {
			delete ownershipTicket[key];
		});

		return ownershipTicket;
	} catch (ex) {
		return null;
	}
}
