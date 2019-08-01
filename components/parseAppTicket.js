const ByteBuffer = require('bytebuffer');
const StdLib = require('@doctormckay/stdlib');
const SteamCrypto = require('@doctormckay/steam-crypto');
const SteamID = require('steamid');

module.exports = parseAppTicket;

/**
 * Parse a Steam app or session ticket and return an object containing its details.
 * @param {Buffer} ticket - The binary appticket
 * @param {boolean} [allowInvalidSignature=false] - If true, won't return null if the ticket has no valid signature
 * @returns {object|null} - object if well-formed ticket (may not be valid), or null if not well-formed
 */
function parseAppTicket(ticket, allowInvalidSignature) {
	// https://github.com/SteamRE/SteamKit/blob/master/Resources/Structs/steam3_appticket.hsl

	if (!ByteBuffer.isByteBuffer(ticket)) {
		ticket = ByteBuffer.wrap(ticket, ByteBuffer.LITTLE_ENDIAN);
	}

	let details = {};

	try {
		let initialLength = ticket.readUint32();
		if (initialLength == 20) {
			// This is a full appticket, with a GC token and session header (in addition to ownership ticket)
			details.authTicket = ticket.slice(ticket.offset - 4, ticket.offset - 4 + 52).toBuffer(); // this is the part that's passed back to Steam for validation

			details.gcToken = ticket.readUint64().toString();
			//details.steamID = new SteamID(ticket.readUint64().toString());
			ticket.skip(8); // the SteamID gets read later on
			details.tokenGenerated = new Date(ticket.readUint32() * 1000);

			if (ticket.readUint32() != 24) {
				// SESSIONHEADER should be 24 bytes.
				return null;
			}

			ticket.skip(8); // unknown 1 and unknown 2
			details.sessionExternalIP = StdLib.IPv4.intToString(ticket.readUint32());
			ticket.skip(4); // filler
			details.clientConnectionTime = ticket.readUint32(); // time the client has been connected to Steam in ms
			details.clientConnectionCount = ticket.readUint32(); // how many servers the client has connected to

			if (ticket.readUint32() + ticket.offset != ticket.limit) {
				// OWNERSHIPSECTIONWITHSIGNATURE sectlength
				return null;
			}
		} else {
			ticket.skip(-4);
		}

		// Start reading the ownership ticket
		let ownershipTicketOffset = ticket.offset;
		let ownershipTicketLength = ticket.readUint32(); // including itself, for some reason
		if (ownershipTicketOffset + ownershipTicketLength != ticket.limit && ownershipTicketOffset + ownershipTicketLength + 128 != ticket.limit) {
			return null;
		}

		let i, j, dlc;

		details.version = ticket.readUint32();
		details.steamID = new SteamID(ticket.readUint64().toString());
		details.appID = ticket.readUint32();
		details.ownershipTicketExternalIP = StdLib.IPv4.intToString(ticket.readUint32());
		details.ownershipTicketInternalIP = StdLib.IPv4.intToString(ticket.readUint32());
		details.ownershipFlags = ticket.readUint32();
		details.ownershipTicketGenerated = new Date(ticket.readUint32() * 1000);
		details.ownershipTicketExpires = new Date(ticket.readUint32() * 1000);
		details.licenses = [];

		let licenseCount = ticket.readUint16();
		for (i = 0; i < licenseCount; i++) {
			details.licenses.push(ticket.readUint32());
		}

		details.dlc = [];

		let dlcCount = ticket.readUint16();
		for (i = 0; i < dlcCount; i++) {
			dlc = {};
			dlc.appID = ticket.readUint32();
			dlc.licenses = [];

			licenseCount = ticket.readUint16();

			for (j = 0; j < licenseCount; j++) {
				dlc.licenses.push(ticket.readUint32());
			}

			details.dlc.push(dlc);
		}

		ticket.readUint16(); // reserved
		if (ticket.offset + 128 == ticket.limit) {
			// Has signature
			details.signature = ticket.slice(ticket.offset, ticket.offset + 128).toBuffer();
		}

		let date = new Date();
		details.isExpired = details.ownershipTicketExpires < date;
		details.hasValidSignature = !!details.signature && SteamCrypto.verifySignature(ticket.slice(ownershipTicketOffset, ownershipTicketOffset + ownershipTicketLength).toBuffer(), details.signature);
		details.isValid = !details.isExpired && (!details.signature || details.hasValidSignature);

		if (!details.hasValidSignature && !allowInvalidSignature) {
			throw new Error("Missing or invalid signature");
		}
	} catch (ex) {
		return null; // not a valid ticket
	}

	return details;
}
