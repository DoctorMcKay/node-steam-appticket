/* eslint-disable */
// Auto-generated by generate-protos script on Tue Aug 20 2024 14:35:03 GMT-0400 (Eastern Daylight Time)

///////////////////////////////////////////////
// encrypted_app_ticket.proto
///////////////////////////////////////////////

export interface EncryptedAppTicket {
	ticket_version_no?: number;
	crc_encryptedticket?: number;
	cb_encrypteduserdata?: number;
	cb_encrypted_appownershipticket?: number;
	encrypted_ticket?: Buffer;
}

