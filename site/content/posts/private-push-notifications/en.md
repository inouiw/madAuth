---
slug: private-push-notifications
title: Push notifications that Apple and Google can't read
description: Why apps need push, what Apple sees, and two ways to keep the text private: an encrypted payload or a wake-up push. With Node.js code, without Amazon SNS.
published: 2026-11-15
---

Every push notification an iPhone shows has passed through Apple's servers, and on Android most pass through Google's. If your server puts the text "Dr. Meier confirmed your appointment for Monday" into a push, Apple can read it. That is not necessary. Messengers such as Signal and Threema send pushes all day, and Apple learns nothing of what they say.

This article explains why apps can't avoid the push services, what those services see, and the two ways to keep the content away from them: an encrypted payload that the phone decrypts, and a push that only wakes the app, which then fetches the message itself. It ends with the server code, which needs no push product from a cloud provider.

## Why apps need push notifications

A phone doesn't let apps run all the time. iOS suspends an app shortly after the user leaves it, and a suspended app can't keep a connection to its server open. If it could, fifty apps would hold fifty connections and wake the radio whenever they liked, and the battery would be empty by noon.

So the operating system keeps one connection open for all apps: to the Apple Push Notification service (APNs) on iOS, to Firebase Cloud Messaging (FCM) on most Android phones. Your server hands a message to that service, and the service delivers it to the phone over the connection that is open anyway.

For an app that is closed, this is the only way to reach the user. On iOS there is no alternative at all. On Android an app can hold its own connection, but as Signal's president [put it](https://mastodon.world/@Mer__edith/111563867509198309), the cost to battery life makes that a false option for most apps.

## What the push service sees

The connection from your server to Apple is encrypted, and so is the one from Apple to the phone. In between, Apple has the notification in the form your server sent it. It sees:

- **The payload**: title, text and every other field, unless you encrypted them yourself.
- **The metadata**: which app sent a push to which device, and when.

This became a public topic in December 2023, when US senator Ron Wyden wrote that governments were demanding push notification records from Apple and Google. Apple has since [required a judge's order](https://qz.com/apple-now-requires-court-orders-in-u-s-to-access-push-1851097319) for them. Whatever the legal bar is, the safest content is the content the push service never had.

Two approaches achieve that. Both rest on the same iOS feature, the *notification service extension*: a small program shipped with your app that iOS starts when a push arrives, before anything is shown. It gets [about 30 seconds](https://developer.apple.com/documentation/usernotifications/modifying-content-in-newly-delivered-notifications) to change the notification's title and text. iOS runs it only if the push carries `"mutable-content": 1` and some alert text.

## Approach 1: an encrypted payload, decrypted on the device

The server encrypts the notification's content with a key that only the device can use, and sends the ciphertext as a custom field of the push. The visible text is a placeholder:

```json
{
  "aps": { "alert": "New message", "mutable-content": 1 },
  "sealed": "BGk3…"
}
```

On the phone, the extension decrypts `sealed` and replaces the placeholder with the real text. If decryption fails, the user sees "New message". Apple's own documentation for the extension uses exactly this as its example.

The key comes from the app: on first start it makes a key pair, keeps the private key in the keychain and sends the public key to your server together with the device token. The keychain item needs two settings: an access group that the extension shares, and the accessibility `kSecAttrAccessibleAfterFirstUnlock`. With the default, the extension can't read the key while the phone is locked, and every push on a locked phone shows the placeholder. The server encrypts each push to that public key:

```ts
import { createCipheriv, createECDH, hkdfSync, randomBytes } from 'node:crypto';

// devicePublicKey: the P-256 public key the app registered (65 bytes, X9.63 format)
function seal(devicePublicKey: Buffer, text: string): string {
  const ephemeral = createECDH('prime256v1');
  const ephemeralPublicKey = ephemeral.generateKeys();
  const shared = ephemeral.computeSecret(devicePublicKey);
  const key = Buffer.from(hkdfSync('sha256', shared, ephemeralPublicKey, 'push-v1', 32));
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return Buffer.concat([ephemeralPublicKey, nonce, ciphertext, cipher.getAuthTag()]).toString('base64');
}
```

The extension reverses it with CryptoKit:

```swift
func open(_ sealed: String, with privateKey: P256.KeyAgreement.PrivateKey) throws -> String {
  guard let data = Data(base64Encoded: sealed), data.count > 65 + 12 + 16 else {
    throw CocoaError(.coderInvalidValue)
  }
  let ephemeralPublicKey = data.prefix(65)
  let shared = try privateKey.sharedSecretFromKeyAgreement(
    with: P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey))
  let key = shared.hkdfDerivedSymmetricKey(
    using: SHA256.self, salt: ephemeralPublicKey, sharedInfo: Data("push-v1".utf8), outputByteCount: 32)
  let box = try AES.GCM.SealedBox(combined: data.dropFirst(65))
  return String(decoding: try AES.GCM.open(box, using: key), as: UTF8.self)
}
```

Who does it this way:

- **Proton Mail.** On each login the app makes a key pair and sends the public key to Proton's push server, which encrypts every push with it; the extension decrypts with the private key from the keychain ([Proton's description](https://proton.me/blog/ios-security-model)).
- **Threema**, in part. Its push carries an encrypted payload with the sender's ID and nickname and the message's ID, under a key Apple doesn't know. The message itself is not in it, not even encrypted: the app downloads it afterwards ([Threema's FAQ](https://threema.com/en/faq/privacy-push)). So Threema combines both approaches.

Put the message's id inside the encrypted text, so the app can ignore a ciphertext it has already shown: nothing else stops someone who holds an old push from sending it again.

What it costs: a key per device to register and to replace when the user signs in again, and a size limit, since APNs refuses payloads [over 4 KB](https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification) and base64 makes the ciphertext a third larger. In return it works without a second network request, so the notification appears even on a bad connection.

## Approach 2: a wake-up push, then fetch the message

The push carries nothing worth protecting. At most it holds an id:

```json
{
  "aps": { "alert": "New message", "mutable-content": 1 },
  "id": "msg_8f3a"
}
```

The extension uses the id to fetch the message from your own server, over your own TLS connection and with the user's credentials, and puts its text into the notification:

```swift
class NotificationService: UNNotificationServiceExtension {
  private let lock = NSLock()
  private var contentHandler: ((UNNotificationContent) -> Void)?
  private var placeholder: UNNotificationContent?

  override func didReceive(
    _ request: UNNotificationRequest,
    withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
  ) {
    self.contentHandler = contentHandler
    placeholder = request.content
    guard let id = request.content.userInfo["id"] as? String else { return finish(request.content) }
    Task {
      // Your API, called with the user's token from the shared keychain.
      guard let message = try? await fetchMessage(id) else { return finish(request.content) }
      let content = request.content.mutableCopy() as! UNMutableNotificationContent
      content.title = message.sender
      content.body = message.text
      finish(content)
    }
  }

  // Out of time: show the placeholder the push came with.
  override func serviceExtensionTimeWillExpire() {
    finish(placeholder)
  }

  // Calls the handler once, whichever comes first: the fetched message or the timeout.
  private func finish(_ content: UNNotificationContent?) {
    lock.lock()
    let handler = contentHandler
    contentHandler = nil
    lock.unlock()
    if let content { handler?(content) }
  }
}
```

Who does it this way:

- **Signal.** Its pushes "simply act as a ping that tells the app to wake up" and don't reveal who sent a message, in the words of [Signal's president](https://mastodon.world/@Mer__edith/111563866152334347). The app fetches the encrypted message and decrypts it on the device.
- **Matrix clients such as Element.** A Matrix server can push in the format `event_id_only`: the push holds the ids of the event and the room, the unread counts and the device's push key, and [nothing about the content](https://spec.matrix.org/latest/push-gateway-api/). The app fetches the event from its homeserver.
- **Threema on Android**, where the FCM payload is empty.

WhatsApp's messages are end-to-end encrypted too, but we found no public description of what its pushes carry, so it is not on either list.

What it costs: the extension needs a network connection and a valid sign-in within its 30 seconds (the access token in the keychain needs the same two settings as the key in approach 1), and every notification is one more request to your server. In return there is no key to manage and no size limit.

Why not a silent *background push* (`content-available`) that wakes the whole app? Because iOS treats those as low priority: Apple's documentation says not to send more than [two or three per hour](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app), and delivery isn't guaranteed. A visible push with an extension is not held back in this way. The price is that a notification always appears, even if the fetch finds nothing to show; hiding it needs an [entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.usernotifications.filtering) that Apple grants on request.

## Which one to choose

| | Encrypted payload | Wake-up and fetch |
| --- | --- | --- |
| Apple sees | ciphertext, metadata | an id at most, metadata |
| Keys | one key pair per device | none |
| Size limit | 4 KB including encryption overhead | none |
| Needs a connection on arrival | no | yes |
| Load on your server | the push only | the push and one request per notification |

If you have no keys on the devices yet, start with wake-up and fetch: it is a few lines on the server and one extension in the app. Choose the encrypted payload when notifications must arrive on poor connections, or when the fetch would be too much load.

## What neither approach hides

- **The metadata.** Apple still knows that your app sent this device a push at this moment. Sending pushes at random times as decoys is the only countermeasure, and almost nobody does it.
- **Your own server.** In both examples above the server knows the text, because it encrypts or serves it. That keeps third parties out, which is the goal here. If your server must not read messages either, the sender's device has to encrypt them, as in Signal: the push design stays the same, and the extension decrypts what it fetched.
- **The notification on the phone.** Once the text is shown, it is on the phone outside your app's control. In April 2026 it was [reported](https://andreafortuna.org/2026/04/11/signal-fbi-iphone-notifications-forensics/) that investigators recovered incoming Signal messages, whose text had been shown in notifications, from an iPhone's notification database after the app had been removed. Offer a setting that keeps the content out of notifications, as Signal does.

## You don't need Amazon SNS for this

Cloud providers sell push as a product: Amazon SNS (Simple Notification Service) with its [mobile push](https://docs.aws.amazon.com/sns/latest/dg/sns-mobile-application-as-subscriber.html) feature, AWS End User Messaging (which took over the push channel of the former Amazon Pinpoint), Azure Notification Hubs. They don't deliver anything themselves. They take your message and call APNs or FCM, as your server could. What they add is one API for several platforms and fan-out to many devices. What they also add is one more company that handles every payload and every device token.

Sending to APNs directly is one HTTP/2 request: a `POST` to `https://api.push.apple.com/3/device/<device token>` with the payload as JSON and a signed token in the `authorization` header. The token is a JWT signed with a key file (`.p8`) from your Apple developer account. Any server with internet access can do that.

The details are what a library is for: APNs wants the token [renewed](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns) at most every 20 and at least every 60 minutes, expects one long-lived connection, and answers with status codes you have to act on. For Node.js, [`@parse/node-apn`](https://github.com/parse-community/node-apn) does this:

```ts
import apn from '@parse/node-apn';

// One provider per process: it keeps the connection to Apple open.
const provider = new apn.Provider({
  token: {
    key: process.env.APNS_KEY!, // the content of the .p8 file
    keyId: process.env.APNS_KEY_ID!,
    teamId: process.env.APNS_TEAM_ID!,
  },
  production: true,
});

async function notify(device: { token: string; publicKey: Buffer }, message: { id: string; text: string }) {
  const note = new apn.Notification();
  note.topic = 'com.example.app'; // the app's bundle id
  note.pushType = 'alert';
  note.alert = 'New message'; // the placeholder
  note.mutableContent = true; // run the extension
  note.payload = { id: message.id }; // approach 2
  // note.payload = { sealed: seal(device.publicKey, message.text) }; // approach 1

  const { failed } = await provider.send(note, device.token);
  // 410: the app was removed from the device. Stop sending to this token.
  if (failed.some((failure) => failure.status === 410)) await deleteDevice(device.token);
}
```

That is the whole server side. Keep the `.p8` key where your other secrets are: it can send to every user of the app. And don't log payloads or device tokens.

For Android, FCM is an HTTP API in the same way, with Google's `firebase-admin` library, and both approaches work there with *data messages*, which the app handles itself.

## Where sign-in comes in

Both approaches depend on knowing whose device it is. The request that registers a device token (and, for approach 1, the public key) has to come from a signed-in user, or anyone could subscribe their phone to someone else's notifications. The fetch in approach 2 is an ordinary API call with the user's access token, which the extension reads from the keychain it shares with the app. And when the user signs out, the server deletes the device token, so the next push doesn't reach a phone that is no longer theirs.

[madAuth](/) is an open-source authentication server you host yourself. It signs users in to native apps as an OpenID Connect provider, with the authorization code flow with PKCE and refresh tokens, so your API can check who registers a device and who fetches a message. Like the push code above, it runs on your own infrastructure, without a third party in between.

## Summary

- A closed app can only be reached through Apple's or Google's push service, and the service can read whatever your server puts into a push.
- Encrypted payload: the server encrypts to a key on the device, the notification service extension decrypts. Proton Mail does this, and Threema for the sender's name.
- Wake-up and fetch: the push holds an id at most, the extension fetches the message from your server. Signal and Matrix clients do this.
- The metadata stays visible either way: which app, which device, when.
- APNs is an HTTP API. A library such as `@parse/node-apn` is enough; a push product such as Amazon SNS only adds a party.
