import {sha1, crc32} from '@doctormckay/stdlib/hashing';
import SteamCrypto from '@doctormckay/steam-crypto';

import Protos from '../protobuf-generated/load';
import {parseAppTicket} from './parseAppTicket';
import {DecodedEncryptedAppTicket} from '../index';
import type {EncryptedAppTicket as EncryptedAppTicketType} from '../protobuf-generated/types';

/**
 *
 * @param {Buffer} ticket - The raw encrypted appticket
 * @param {Buffer|string} encryptionKey - The app's encryption key, either raw hex or a Buffer
 * @returns {DecodedEncryptedAppTicket|null}
 */
export function parseEncryptedAppTicket(ticket: Buffer, encryptionKey: Buffer|string): DecodedEncryptedAppTicket|null {
	try {
		let outer = Protos.EncryptedAppTicket.decode(ticket) as EncryptedAppTicketType;
		let key = typeof encryptionKey === 'string' ? Buffer.from(encryptionKey, 'hex') : encryptionKey;
		let decrypted = SteamCrypto.symmetricDecrypt(outer.encrypted_ticket, key);

		if (crc32(decrypted) != outer.crc_encryptedticket) {
			return null;
		}

		// the beginning is the user-supplied data
		let userData = decrypted.slice(0, outer.cb_encrypteduserdata);
		let ownershipTicketLength = decrypted.readUInt32LE(outer.cb_encrypteduserdata);
		// @ts-ignore
		let ownershipTicket:DecodedEncryptedAppTicket = parseAppTicket(decrypted.slice(outer.cb_encrypteduserdata, outer.cb_encrypteduserdata + ownershipTicketLength), true);
		if (ownershipTicket) {
			ownershipTicket.userData = userData;
		}

		let remainderOffset = 0;
		if (outer.ticket_version_no == 2) {
			remainderOffset += 8 + 8 + 4;
			let readOffset = outer.cb_encrypteduserdata + ownershipTicketLength;
			// @ts-ignore
			ownershipTicket.unknown2 = decrypted.readBigUint64LE(readOffset).toString();
			readOffset += 8;
			// @ts-ignore
			ownershipTicket.unknown3 = decrypted.readBigUint64LE(readOffset).toString();
			readOffset += 8;
			// @ts-ignore
			ownershipTicket.unknown4 = decrypted.readUInt32LE(readOffset);
		}

		let remainder = decrypted.slice(outer.cb_encrypteduserdata + ownershipTicketLength + remainderOffset);
		if (remainder.length >= 8 + 20) {
			// salted sha1 hash
			let dataToHash = decrypted.slice(0, outer.cb_encrypteduserdata + ownershipTicketLength + remainderOffset);
			let salt = remainder.slice(0, 8);
			let hash = remainder.slice(8, 28);
			remainder = remainder.slice(28);

			if (!hash.equals(sha1(Buffer.concat([dataToHash, salt]), 'buffer'))) {
				return null;
			}

			if (ownershipTicket) {
				// @ts-ignore
				ownershipTicket.unknown1 = remainder.readUInt32LE(0);
			}
		}

		[
			'ownershipTicketExpires',
			'isExpired',
			'hasValidSignature',
			'isValid',
			'unknown1',
			'unknown2',
			'unknown3',
			'unknown4'
		].forEach((key) => {
			delete ownershipTicket[key];
		});

		return ownershipTicket;
	} catch (ex) {
		return null;
	}
}
