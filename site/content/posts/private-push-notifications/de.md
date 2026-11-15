---
slug: private-push-benachrichtigungen
title: Push-Benachrichtigungen, die Apple und Google nicht lesen können
seoTitle: Push-Benachrichtigungen, die Apple nicht lesen kann
description: Warum Apps Push brauchen, was Apple sieht und zwei Wege, den Text privat zu halten: verschlüsselte Nutzlast oder Weck-Push. Mit Node.js-Code, ohne Amazon SNS.
published: 2026-11-15
---

Jede Push-Benachrichtigung, die ein iPhone anzeigt, ist über Apples Server gelaufen, und auf Android laufen die meisten über die von Google. Schreibt Ihr Server den Text „Dr. Meier hat Ihren Termin am Montag bestätigt“ in eine Push-Nachricht, kann Apple ihn lesen. Nötig ist das nicht. Messenger wie Signal und Threema verschicken den ganzen Tag Push-Nachrichten, und Apple erfährt nichts von ihrem Inhalt.

Dieser Artikel erklärt, warum Apps an den Push-Diensten nicht vorbeikommen, was diese Dienste sehen, und die zwei Wege, den Inhalt von ihnen fernzuhalten: eine verschlüsselte Nutzlast, die das Smartphone entschlüsselt, und eine Push-Nachricht, die die App nur weckt, worauf diese die Nachricht selbst abholt. Am Ende steht der Servercode, der ohne das Push-Produkt eines Cloud-Anbieters auskommt.

## Warum Apps Push-Benachrichtigungen brauchen

Ein Smartphone lässt Apps nicht dauernd laufen. iOS hält eine App an, kurz nachdem der Nutzer sie verlassen hat, und eine angehaltene App kann keine Verbindung zu ihrem Server offen halten. Könnte sie es, hielten fünfzig Apps fünfzig Verbindungen und weckten das Funkmodul, wann sie wollten, und der Akku wäre mittags leer.

Deshalb hält das Betriebssystem eine einzige Verbindung für alle Apps offen: auf iOS zum Apple Push Notification service (APNs), auf den meisten Android-Geräten zu Firebase Cloud Messaging (FCM). Ihr Server übergibt eine Nachricht an diesen Dienst, und der Dienst stellt sie über die ohnehin offene Verbindung zu.

Eine geschlossene App erreicht den Nutzer nur auf diesem Weg. Auf iOS gibt es keine Alternative. Auf Android kann eine App eine eigene Verbindung halten, doch wie die Präsidentin von Signal [schreibt](https://mastodon.world/@Mer__edith/111563867509198309), kostet das so viel Akku, dass es für die meisten Apps keine echte Option ist.

## Was der Push-Dienst sieht

Die Verbindung von Ihrem Server zu Apple ist verschlüsselt, die von Apple zum Smartphone ebenfalls. Dazwischen liegt die Benachrichtigung bei Apple so vor, wie Ihr Server sie geschickt hat. Apple sieht:

- **Die Nutzlast** (Payload): Titel, Text und jedes weitere Feld, sofern Sie sie nicht selbst verschlüsselt haben.
- **Die Metadaten**: welche App wann an welches Gerät eine Push-Nachricht geschickt hat.

Öffentlich diskutiert wird das seit Dezember 2023, als US-Senator Ron Wyden schrieb, dass Regierungen von Apple und Google Daten über Push-Benachrichtigungen verlangen. Apple gibt sie seitdem nur noch [auf richterliche Anordnung](https://qz.com/apple-now-requires-court-orders-in-u-s-to-access-push-1851097319) heraus. Wie hoch die rechtliche Hürde auch ist: Am sichersten ist der Inhalt, den der Push-Dienst nie hatte.

Zwei Ansätze erreichen das. Beide beruhen auf derselben iOS-Funktion, der *Notification Service Extension*: einem kleinen Programm, das mit Ihrer App ausgeliefert wird und das iOS startet, wenn eine Push-Nachricht ankommt, bevor etwas angezeigt wird. Es hat [etwa 30 Sekunden](https://developer.apple.com/documentation/usernotifications/modifying-content-in-newly-delivered-notifications), um Titel und Text der Benachrichtigung zu ändern. iOS führt es nur aus, wenn die Push-Nachricht `"mutable-content": 1` und einen Anzeigetext enthält.

## Ansatz 1: verschlüsselte Nutzlast, auf dem Gerät entschlüsselt

Der Server verschlüsselt den Inhalt der Benachrichtigung mit einem Schlüssel, den nur das Gerät verwenden kann, und schickt den Geheimtext als eigenes Feld der Push-Nachricht. Der sichtbare Text ist ein Platzhalter:

```json
{
  "aps": { "alert": "Neue Nachricht", "mutable-content": 1 },
  "sealed": "BGk3…"
}
```

Auf dem Smartphone entschlüsselt die Extension `sealed` und ersetzt den Platzhalter durch den echten Text. Schlägt das Entschlüsseln fehl, sieht der Nutzer „Neue Nachricht“. Apples eigene Dokumentation der Extension verwendet genau dieses Beispiel.

Der Schlüssel kommt von der App: Beim ersten Start erzeugt sie ein Schlüsselpaar, legt den privaten Schlüssel im Schlüsselbund ab und schickt den öffentlichen Schlüssel zusammen mit dem Geräte-Token an Ihren Server. Der Eintrag im Schlüsselbund braucht zwei Einstellungen: eine Zugriffsgruppe, die die App mit der Extension teilt, und die Zugreifbarkeit `kSecAttrAccessibleAfterFirstUnlock`. Mit der Voreinstellung kann die Extension den Schlüssel nicht lesen, solange das Smartphone gesperrt ist, und jede Push-Nachricht auf einem gesperrten Gerät zeigt den Platzhalter. Der Server verschlüsselt jede Push-Nachricht für diesen öffentlichen Schlüssel:

```ts
import { createCipheriv, createECDH, hkdfSync, randomBytes } from 'node:crypto';

// devicePublicKey: der öffentliche P-256-Schlüssel, den die App registriert hat (65 Bytes, X9.63-Format)
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

Die Extension kehrt das mit CryptoKit um:

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

Wer es so macht:

- **Proton Mail.** Bei jeder Anmeldung erzeugt die App ein Schlüsselpaar und schickt den öffentlichen Schlüssel an Protons Push-Server, der jede Push-Nachricht damit verschlüsselt; die Extension entschlüsselt mit dem privaten Schlüssel aus dem Schlüsselbund ([Protons Beschreibung](https://proton.me/blog/ios-security-model)).
- **Threema**, zum Teil. Die Push-Nachricht enthält eine verschlüsselte Nutzlast mit ID und Nickname des Absenders und der ID der Nachricht, unter einem Schlüssel, den Apple nicht kennt. Die Nachricht selbst steht nicht darin, auch nicht verschlüsselt: Die App lädt sie anschließend herunter ([Threemas FAQ](https://threema.com/en/faq/privacy-push)). Threema verbindet also beide Ansätze.

Nehmen Sie die ID der Nachricht in den verschlüsselten Text auf, damit die App einen Geheimtext ignorieren kann, den sie schon angezeigt hat: Sonst hindert nichts jemanden, der eine alte Push-Nachricht besitzt, daran, sie erneut zu senden.

Der Preis: ein Schlüssel pro Gerät, der registriert und bei erneuter Anmeldung ersetzt werden muss, und eine Größengrenze, denn APNs lehnt Nutzlasten [über 4 KB](https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification) ab, und Base64 macht den Geheimtext um ein Drittel größer. Dafür kommt der Ansatz ohne zweite Netzwerkanfrage aus, die Benachrichtigung erscheint also auch bei schlechter Verbindung.

## Ansatz 2: ein Weck-Push, dann die Nachricht abholen

Die Push-Nachricht enthält nichts Schützenswertes, höchstens eine ID:

```json
{
  "aps": { "alert": "Neue Nachricht", "mutable-content": 1 },
  "id": "msg_8f3a"
}
```

Mit der ID holt die Extension die Nachricht von Ihrem eigenen Server ab, über Ihre eigene TLS-Verbindung und mit den Zugangsdaten des Nutzers, und setzt den Text in die Benachrichtigung ein:

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
      // Ihre API, aufgerufen mit dem Token des Nutzers aus dem geteilten Schlüsselbund.
      guard let message = try? await fetchMessage(id) else { return finish(request.content) }
      let content = request.content.mutableCopy() as! UNMutableNotificationContent
      content.title = message.sender
      content.body = message.text
      finish(content)
    }
  }

  // Zeit abgelaufen: den Platzhalter anzeigen, mit dem die Push-Nachricht kam.
  override func serviceExtensionTimeWillExpire() {
    finish(placeholder)
  }

  // Ruft den Handler einmal auf, je nachdem, was zuerst kommt: die abgeholte Nachricht oder der Zeitablauf.
  private func finish(_ content: UNNotificationContent?) {
    lock.lock()
    let handler = contentHandler
    contentHandler = nil
    lock.unlock()
    if let content { handler?(content) }
  }
}
```

Wer es so macht:

- **Signal.** Die Push-Nachrichten sind nur ein Ping, der die App aufweckt, und verraten nicht, wer geschrieben hat, so die [Präsidentin von Signal](https://mastodon.world/@Mer__edith/111563866152334347). Die App holt die verschlüsselte Nachricht ab und entschlüsselt sie auf dem Gerät.
- **Matrix-Clients wie Element.** Ein Matrix-Server kann im Format `event_id_only` pushen: Die Push-Nachricht enthält die IDs des Ereignisses und des Raums, die Zahl der ungelesenen Nachrichten und den Push-Schlüssel des Geräts, aber [nichts vom Inhalt](https://spec.matrix.org/latest/push-gateway-api/). Die App holt das Ereignis von ihrem Homeserver.
- **Threema auf Android**, wo die FCM-Nutzlast leer ist.

Auch WhatsApp verschlüsselt Nachrichten Ende-zu-Ende. Wir haben aber keine öffentliche Beschreibung gefunden, was seine Push-Nachrichten enthalten, deshalb steht es auf keiner der beiden Listen.

Der Preis: Die Extension braucht innerhalb ihrer 30 Sekunden eine Netzwerkverbindung und eine gültige Anmeldung (das Access-Token im Schlüsselbund braucht dieselben zwei Einstellungen wie der Schlüssel in Ansatz 1), und jede Benachrichtigung ist eine weitere Anfrage an Ihren Server. Dafür gibt es keinen Schlüssel zu verwalten und keine Größengrenze.

Warum kein stiller *Background Push* (`content-available`), der die ganze App weckt? Weil iOS ihn mit niedriger Priorität behandelt: Laut Apples Dokumentation sollten es nicht mehr als [zwei oder drei pro Stunde](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app) sein, und die Zustellung ist nicht garantiert. Eine sichtbare Push-Nachricht mit Extension wird nicht auf diese Weise zurückgehalten. Der Preis ist, dass immer eine Benachrichtigung erscheint, auch wenn das Abholen nichts Anzeigbares ergibt; sie zu unterdrücken erfordert ein [Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.usernotifications.filtering), das Apple auf Antrag vergibt.

## Welcher Ansatz passt

| | Verschlüsselte Nutzlast | Wecken und abholen |
| --- | --- | --- |
| Apple sieht | Geheimtext, Metadaten | höchstens eine ID, Metadaten |
| Schlüssel | ein Schlüsselpaar pro Gerät | keine |
| Größengrenze | 4 KB, die Verschlüsselung zählt mit | keine |
| Braucht bei Ankunft eine Verbindung | nein | ja |
| Last auf Ihrem Server | nur die Push-Nachricht | die Push-Nachricht und eine Anfrage pro Benachrichtigung |

Wenn auf den Geräten noch keine Schlüssel liegen, beginnen Sie mit Wecken und Abholen: ein paar Zeilen auf dem Server und eine Extension in der App. Die verschlüsselte Nutzlast lohnt sich, wenn Benachrichtigungen auch bei schlechter Verbindung ankommen müssen oder das Abholen zu viel Last erzeugt.

## Was keiner der beiden Ansätze verbirgt

- **Die Metadaten.** Apple weiß weiterhin, dass Ihre App diesem Gerät in diesem Moment eine Push-Nachricht geschickt hat. Dagegen helfen nur Push-Nachrichten zu zufälligen Zeiten als Attrappen, und das macht fast niemand.
- **Ihr eigener Server.** In beiden Beispielen kennt der Server den Text, weil er ihn verschlüsselt oder ausliefert. Dritte bleiben damit außen vor, und darum geht es hier. Soll auch Ihr Server die Nachrichten nicht lesen können, muss das Gerät des Absenders sie verschlüsseln, wie bei Signal: Der Aufbau der Push-Nachricht bleibt derselbe, und die Extension entschlüsselt, was sie abgeholt hat.
- **Die Benachrichtigung auf dem Smartphone.** Sobald der Text angezeigt wird, liegt er auf dem Smartphone außerhalb der Kontrolle Ihrer App. Im April 2026 wurde [berichtet](https://andreafortuna.org/2026/04/11/signal-fbi-iphone-notifications-forensics/), dass Ermittler eingegangene Signal-Nachrichten, deren Text in Benachrichtigungen angezeigt worden war, aus der Benachrichtigungsdatenbank eines iPhones wiederhergestellt haben, nachdem die App entfernt worden war. Bieten Sie eine Einstellung an, die den Inhalt aus Benachrichtigungen heraushält, wie Signal es tut.

## Amazon SNS brauchen Sie dafür nicht

Cloud-Anbieter verkaufen Push als Produkt: Amazon SNS (Simple Notification Service) mit seiner Funktion [Mobile Push](https://docs.aws.amazon.com/sns/latest/dg/sns-mobile-application-as-subscriber.html), AWS End User Messaging (das den Push-Kanal des früheren Amazon Pinpoint übernommen hat), Azure Notification Hubs. Sie stellen selbst nichts zu. Sie nehmen Ihre Nachricht entgegen und rufen APNs oder FCM auf, wie Ihr Server es auch könnte. Was sie hinzufügen, ist eine API für mehrere Plattformen und das Verteilen an viele Geräte. Was sie außerdem hinzufügen, ist ein weiteres Unternehmen, durch dessen Hände jede Nutzlast und jedes Geräte-Token geht.

Direkt an APNs zu senden ist eine HTTP/2-Anfrage: ein `POST` an `https://api.push.apple.com/3/device/<Geräte-Token>` mit der Nutzlast als JSON und einem signierten Token im Header `authorization`. Das Token ist ein JWT, signiert mit einer Schlüsseldatei (`.p8`) aus Ihrem Apple-Entwicklerkonto. Das kann jeder Server mit Internetzugang.

Für die Details gibt es Bibliotheken: APNs will das Token höchstens alle 20 und mindestens alle 60 Minuten [erneuert](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns) haben, erwartet eine langlebige Verbindung und antwortet mit Statuscodes, auf die Sie reagieren müssen. Für Node.js erledigt das [`@parse/node-apn`](https://github.com/parse-community/node-apn):

```ts
import apn from '@parse/node-apn';

// Ein Provider pro Prozess: Er hält die Verbindung zu Apple offen.
const provider = new apn.Provider({
  token: {
    key: process.env.APNS_KEY!, // der Inhalt der .p8-Datei
    keyId: process.env.APNS_KEY_ID!,
    teamId: process.env.APNS_TEAM_ID!,
  },
  production: true,
});

async function notify(device: { token: string; publicKey: Buffer }, message: { id: string; text: string }) {
  const note = new apn.Notification();
  note.topic = 'com.example.app'; // die Bundle-ID der App
  note.pushType = 'alert';
  note.alert = 'Neue Nachricht'; // der Platzhalter
  note.mutableContent = true; // die Extension ausführen
  note.payload = { id: message.id }; // Ansatz 2
  // note.payload = { sealed: seal(device.publicKey, message.text) }; // Ansatz 1

  const { failed } = await provider.send(note, device.token);
  // 410: Die App wurde vom Gerät entfernt. An dieses Token nicht mehr senden.
  if (failed.some((failure) => failure.status === 410)) await deleteDevice(device.token);
}
```

Das ist die gesamte Serverseite. Bewahren Sie den `.p8`-Schlüssel dort auf, wo Ihre anderen Geheimnisse liegen: Mit ihm lässt sich an jeden Nutzer der App senden. Und schreiben Sie weder Nutzlasten noch Geräte-Token ins Log.

Für Android ist FCM in gleicher Weise eine HTTP-API, mit Googles Bibliothek `firebase-admin`, und beide Ansätze funktionieren dort mit *Data Messages*, die die App selbst verarbeitet.

## Wo die Anmeldung ins Spiel kommt

Beide Ansätze setzen voraus, dass der Server weiß, wem ein Gerät gehört. Die Anfrage, die ein Geräte-Token (und für Ansatz 1 den öffentlichen Schlüssel) registriert, muss von einem angemeldeten Nutzer kommen, sonst könnte jeder sein Smartphone für die Benachrichtigungen eines anderen eintragen. Das Abholen in Ansatz 2 ist ein gewöhnlicher API-Aufruf mit dem Access-Token des Nutzers, das die Extension aus dem Schlüsselbund liest, den sie mit der App teilt. Und meldet sich der Nutzer ab, löscht der Server das Geräte-Token, damit die nächste Push-Nachricht kein Smartphone erreicht, das nicht mehr seines ist.

[madAuth](/) ist ein quelloffener Authentifizierungsserver, den Sie selbst betreiben. Er meldet Nutzer nativer Apps als OpenID-Connect-Provider an, mit dem Authorization Code Flow mit PKCE und Refresh-Tokens, sodass Ihre API prüfen kann, wer ein Gerät registriert und wer eine Nachricht abholt. Wie der Push-Code oben läuft er auf Ihrer eigenen Infrastruktur, ohne einen Dritten dazwischen.

## Zusammenfassung

- Eine geschlossene App ist nur über den Push-Dienst von Apple oder Google erreichbar, und der Dienst kann lesen, was Ihr Server in eine Push-Nachricht schreibt.
- Verschlüsselte Nutzlast: Der Server verschlüsselt für einen Schlüssel auf dem Gerät, die Notification Service Extension entschlüsselt. So macht es Proton Mail, und Threema für den Namen des Absenders.
- Wecken und abholen: Die Push-Nachricht enthält höchstens eine ID, die Extension holt die Nachricht von Ihrem Server. So machen es Signal und Matrix-Clients.
- Die Metadaten bleiben in beiden Fällen sichtbar: welche App, welches Gerät, wann.
- APNs ist eine HTTP-API. Eine Bibliothek wie `@parse/node-apn` genügt; ein Push-Produkt wie Amazon SNS fügt nur einen Beteiligten hinzu.
