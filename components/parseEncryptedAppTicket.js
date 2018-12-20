const parseEncryptedAppTicketEx = require('./parseEncryptedAppTicketEx');

module.exports = parseEncryptedAppTicket;

/**
 *
 * @param {Buffer} ticket - The raw encrypted appticket
 * @param {Buffer|string} encryptionKey - The app's encryption key, either raw hex or a Buffer
 * @returns {object}
 */
function parseEncryptedAppTicket(ticket, encryptionKey) {
	let parsed = parseEncryptedAppTicketEx(ticket, encryptionKey);
	if (!parsed) {
		return parsed;
	}

	[
		'ownershipTicketExpires',
		'isExpired',
		'hasValidSignature',
		'isValid',
		'unknown1'
	].forEach((key) => {
		delete parsed[key];
	});

	return parsed;
}
