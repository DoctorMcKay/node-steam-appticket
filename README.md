# Steam App Ticket Parser

This module enables you to parse Steam encrypted app tickets provided you know the proper decryption key. This allows you
to authenticate Steam users from your game backend without needing to verify with Steam that the ticket is valid.

## Usage

### parseEncryptedAppTicket(ticket, encryptionKey)
- `ticket` - A `Buffer` containing the encrypted app ticket
- `encryptionKey` - A `Buffer` or hex string containing the app's decryption key

```js
const AppTicket = require('steam-appticket');
// OR
import AppTicket from 'steam-appticket';
// OR
import {parseEncryptedAppTicket} from 'steam-appticket';

const ticket = Buffer.from('<ticket hex>', 'hex');
const decryptionKey = '6ef99262a7da9e9979737d0822d5d66d03eb0c580b305981a505648b3e21b12e';

console.log(AppTicket.parseEncryptedAppTicket(ticket, decryptionKey));
```

`parseEncryptedAppTicket` returns an object containing these properties:

- `version` - The version of the app ownership ticket
- `steamID` - The ticket owner's SteamID, as a [`SteamID` object](https://www.npmjs.com/package/steamid)
- `appID` - The ID of the app this ticket authenticates
- `ownershipTicketExternalIP` - A string containing the external IP address of the ticket owner as reported by Steam at the time when the ownership ticket was assigned
- `ownershipTicketInternalIP` - Same as above but for their internal IP. If the ticket was generated by steam-user then this may be random
- `ownershipFlags` - A number containing some (probably uninteresting) flags
- `ownershipTicketGenerated` - A `Date` object containing the time when this ticket's ownership ticket was assigned
- `licenses` - An array of integers containing the package IDs for all the licenses the ticket owner owns which grant them this app
- `dlc` - An array of objects, each of which contains:
	- `appID` - The AppID of the piece of DLC
	- `licenses` - An array of integers containing the package IDs for all the licenses the ticket owner owns which grant them this DLC. Seems to not work right now.
- `userData` - Whatever data was sent by the user to Steam when they requested the ticket

Returns `null` if the provided ticket could not be parsed or could not be verified for authenticity. If you get data
returned, it is **guaranteed** that it has not been tampered with, provided your encryption key has not been compromised.

To determine if a ticket is valid, you should do the following:

1. Check that the AppID matches the AppID you expect
2. If the user has already supplied their SteamID, make sure it matches the one in the ticket
3. Make sure it hasn't been generated too far in the past for your liking
4. If you built a nonce into the ticket, make sure the `userData` matches what you expect 

If you want to have a relatively long grace period in which an encrypted app ticket can be used, but you also want to
make sure that it wasn't *reused*, you can send a nonce to the client and have them build that into their encrypted app
ticket's `userData`.

## Parsing Unencrypted App Tickets

### parseAppTicket(ticket[, allowInvalidSignature])
- `ticket` - A `Buffer` containing the ticket you want to parse
- `allowInvalidSignature` - Optional. Pass `true` to get back data even if the ticket has no valid signature. Defaults to `false`.

```js
const AppTicket = require('steam-appticket');
// OR
import AppTicket from 'steam-appticket';
// OR
import {parseAppTicket} from 'steam-appticket';

const ticket = Buffer.from('<ticket hex>', 'hex');
console.log(AppTicket.parseAppTicket(ticket));
```

You can also parse an app ticket that isn't encrypted. To do so, use `AppTicket.parseAppTicket(ticket)`. It returns
an object with these properties:

- `authTicket` - A Buffer containing the part of the ticket that's sent to Steam for validation
- `gcToken` - A string containing a 64-bit number which is the ticket's "GC token" (GC stands for "game connect")
- `tokenGenerated` - A `Date` object containing the time when this ticket's GC token was generated
- `sessionExternalIP` - A string containing the ticket owner's external IP address (as reported by Steam) at time of connection
    - Note that this is not authenticated and may be spoofed
- `clientConnectionTime` - Time in milliseconds the ticket owner was connected to Steam when they generated this ticket (?)
- `clientConnectionCount` - Number of tickets generated by the ticket owner for this Steam connection (?)
- `version` - The version of the app ownership ticket
- `steamID` - The ticket owner's SteamID, as a [`SteamID` object](https://www.npmjs.com/package/steamid)
- `appID` - The ID of the app this ticket authenticates
- `ownershipTicketExternalIP` - A string containing the external IP address of the ticket owner as reported by Steam at the time when the ownership ticket was assigned
    - This **is** authenticated and may not be spoofed, although it could be outdated since ownership tickets are cached for multiple days
- `ownershipTicketInternalIP` - Same as above but for their internal IP. If the ticket was generated by steam-user then this may be random
    - This is not authenticated and may be spoofed
- `ownershipFlags` - A number containing some (probably uninteresting) flags
- `ownershipTicketGenerated` - A `Date` object containing the time when this ticket's ownership ticket was assigned
- `ownershipTicketExpires` - Same as above but for when the ownership ticket expires
- `licenses` - An array of integers containing the package IDs for all the licenses the ticket owner owns which grant them this app
- `dlc` - An array of objects, each of which contains:
	- `appID` - The AppID of the piece of DLC
	- `licenses` - An array of integers containing the package IDs for all the licenses the ticket owner owns which grant them this DLC. Seems to not work right now.
- `signature` - A `Buffer` containing the signature for the app ownership ticket (uninteresting to you)
- `isExpired` - A boolean indicating whether the app ownership ticket is expired
- `hasValidSignature` - A boolean indicating whether the app ownership ticket signature is valid
- `isValid` - A boolean indicating whether the app ownership ticket is valid
	- If you passed `true` for `allowInvalidSignature` and the signature is missing, this will be true if the ticket is not expired!

Note that you shouldn't rely on an unencrypted app ticket without first
[verifying it with Steam](https://partner.steamgames.com/doc/webapi/ISteamUserAuth#AuthenticateUserTicket).
