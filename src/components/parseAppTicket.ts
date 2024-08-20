import ByteBuffer from 'bytebuffer';
import {intToString} from '@doctormckay/stdlib/ipv4';
import SteamCrypto from '@doctormckay/steam-crypto';
import SteamID from 'steamid';

import {AppOwnershipTicket, AppTicket} from '../index';

/**
 * Parse a Steam app or session ticket and return an object containing its details.
 * @param {Buffer} ticket - The binary appticket
 * @param {boolean} [allowInvalidSignature=false] - If true, won't return null if the ticket has no valid signature
 * @returns {AppOwnershipTicket|AppTicket|null} - object if well-formed ticket (may not be valid), or null if not well-formed
 */
export function parseAppTicket(ticket: Buffer|ByteBuffer, allowInvalidSignature: boolean = false): AppOwnershipTicket|AppTicket|null {
	// https://github.com/SteamRE/SteamKit/blob/master/Resources/Structs/steam3_appticket.hsl

	if (!ByteBuffer.isByteBuffer(ticket)) {
		ticket = ByteBuffer.wrap(ticket, ByteBuffer.LITTLE_ENDIAN);
	}

	let bytebufferTicket = ticket as ByteBuffer;

	// @ts-ignore
	let details:AppTicket = {};

	try {
		let initialLength = bytebufferTicket.readUint32();
		if (initialLength == 20) {
			// This is a full appticket, with a GC token and session header (in addition to ownership ticket)
			details.authTicket = bytebufferTicket.slice(bytebufferTicket.offset - 4, bytebufferTicket.offset - 4 + 52).toBuffer(); // this is the part that's passed back to Steam for validation

			details.gcToken = bytebufferTicket.readUint64().toString();
			//details.steamID = new SteamID(ticket.readUint64().toString());
			bytebufferTicket.skip(8); // the SteamID gets read later on
			details.tokenGenerated = new Date(bytebufferTicket.readUint32() * 1000);

			if (bytebufferTicket.readUint32() != 24) {
				// SESSIONHEADER should be 24 bytes.
				return null;
			}

			bytebufferTicket.skip(8); // unknown 1 and unknown 2
			details.sessionExternalIP = intToString(bytebufferTicket.readUint32());
			bytebufferTicket.skip(4); // filler
			details.clientConnectionTime = bytebufferTicket.readUint32(); // time the client has been connected to Steam in ms
			details.clientConnectionCount = bytebufferTicket.readUint32(); // how many servers the client has connected to

			if (bytebufferTicket.readUint32() + bytebufferTicket.offset != bytebufferTicket.limit) {
				// OWNERSHIPSECTIONWITHSIGNATURE sectlength
				return null;
			}
		} else {
			bytebufferTicket.skip(-4);
		}

		// Start reading the ownership ticket
		let ownershipTicketOffset = bytebufferTicket.offset;
		let ownershipTicketLength = bytebufferTicket.readUint32(); // including itself, for some reason
		if (ownershipTicketOffset + ownershipTicketLength != bytebufferTicket.limit && ownershipTicketOffset + ownershipTicketLength + 128 != bytebufferTicket.limit) {
			return null;
		}

		let i, j, dlc;

		details.version = bytebufferTicket.readUint32();
		details.steamID = new SteamID(bytebufferTicket.readUint64().toString());
		details.appID = bytebufferTicket.readUint32();
		details.ownershipTicketExternalIP = intToString(bytebufferTicket.readUint32());
		details.ownershipTicketInternalIP = intToString(bytebufferTicket.readUint32());
		details.ownershipFlags = bytebufferTicket.readUint32();
		details.ownershipTicketGenerated = new Date(bytebufferTicket.readUint32() * 1000);
		details.ownershipTicketExpires = new Date(bytebufferTicket.readUint32() * 1000);
		details.licenses = [];

		let licenseCount = bytebufferTicket.readUint16();
		for (i = 0; i < licenseCount; i++) {
			details.licenses.push(bytebufferTicket.readUint32());
		}

		details.dlc = [];

		let dlcCount = bytebufferTicket.readUint16();
		for (i = 0; i < dlcCount; i++) {
			dlc = {};
			dlc.appID = bytebufferTicket.readUint32();
			dlc.licenses = [];

			licenseCount = bytebufferTicket.readUint16();

			for (j = 0; j < licenseCount; j++) {
				dlc.licenses.push(bytebufferTicket.readUint32());
			}

			details.dlc.push(dlc);
		}

		bytebufferTicket.readUint16(); // reserved
		if (bytebufferTicket.offset + 128 == bytebufferTicket.limit) {
			// Has signature
			details.signature = bytebufferTicket.slice(bytebufferTicket.offset, bytebufferTicket.offset + 128).toBuffer();
		}

		let date = new Date();
		details.isExpired = details.ownershipTicketExpires < date;
		details.hasValidSignature = !!details.signature && SteamCrypto.verifySignature(bytebufferTicket.slice(ownershipTicketOffset, ownershipTicketOffset + ownershipTicketLength).toBuffer(), details.signature);
		details.isValid = !details.isExpired && (!details.signature || details.hasValidSignature);

		if (!details.hasValidSignature && !allowInvalidSignature) {
			throw new Error('Missing or invalid signature');
		}
	} catch (ex) {
		return null; // not a valid ticket
	}

	return details;
}
