---
slug: passkeys-erklaert
title: Passkeys erklärt: So funktioniert WebAuthn – und deshalb scheitert Phishing
description: Was ein Passkey ist, was bei einer WebAuthn-Anmeldung passiert, warum eine gefälschte Seite leer ausgeht und worauf der Server achten muss, wenn Sie Passkeys in Ihre Web-App einbauen.
published: 2026-10-15
---

Ein Passkey ersetzt das Passwort durch ein Schlüsselpaar. Das Gerät oder der Passwortmanager des Nutzers erzeugt für jede Website ein eigenes Schlüsselpaar, behält den privaten Schlüssel und gibt der Website nur den öffentlichen. Bei der Anmeldung beweist das Gerät, dass es den privaten Schlüssel besitzt – nachdem der Nutzer es mit Fingerabdruck, Gesicht oder PIN entsperrt hat. Es gibt nichts einzutippen, nichts zu merken und nichts, was eine gefälschte Anmeldeseite abgreifen könnte.

Dieser Artikel erklärt, wie das technisch funktioniert (der Standard heißt WebAuthn), warum Passkeys Phishing verhindern, wo Passwörter und Einmalcodes versagen, und worauf Sie achten müssen, wenn Sie Passkeys in Ihre eigene Web-App einbauen.

## Was ein Passkey ist

Ein Passkey ist ein Public-Key-Zugangsschlüssel, der an genau eine Website gebunden ist, die *Relying Party*. Drei Beteiligte wirken zusammen:

- **Der Authenticator** erzeugt und verwahrt den privaten Schlüssel. Das kann das Smartphone oder der Laptop selbst sein (Touch ID, Windows Hello, die Displaysperre von Android), ein Passwortmanager wie iCloud-Schlüsselbund, Google Passwortmanager oder 1Password, oder ein Hardware-Sicherheitsschlüssel.
- **Der Browser** vermittelt. Er spricht mit dem Authenticator und teilt ihm – das ist der entscheidende Punkt – mit, welche Website fragt.
- **Der Server** speichert den öffentlichen Schlüssel und prüft damit Signaturen.

Die meisten Passkeys werden heute *synchronisiert*: Der Passwortmanager kopiert sie Ende-zu-Ende-verschlüsselt auf die anderen Geräte des Nutzers, ein neues Smartphone hat die Passkeys also schon. Ein Sicherheitsschlüssel dagegen behält seine Passkeys für sich. Auf einem Rechner ohne die Passkeys des Nutzers zeigt der Browser einen QR-Code: Der Nutzer scannt ihn mit dem Smartphone, das Smartphone antwortet, und Bluetooth bestätigt, dass es tatsächlich in der Nähe ist.

## Was bei der Anmeldung passiert

Jede Passkey-Anmeldung ist ein kleines Challenge-Response-Verfahren:

1. Der Server erzeugt eine zufällige **Challenge**, einen Wert, den er noch nie verwendet hat und genau einmal akzeptiert.
2. Der Browser gibt die Challenge an den Authenticator weiter, zusammen mit dem **Origin** der Seite (zum Beispiel `https://app.example.com`) und der **Relying-Party-ID**, der Domain, zu der der Passkey gehört (zum Beispiel `example.com`).
3. Der Authenticator sucht einen Passkey dieser Domain, **prüft den Nutzer** (Fingerabdruck, Gesicht oder PIN) und **signiert** Challenge, Origin und Domain mit dem privaten Schlüssel.
4. Der Server prüft die Signatur mit dem gespeicherten öffentlichen Schlüssel – und dass die Challenge von ihm stammt, der Origin zu einer seiner Apps gehört und die Domain seine eigene ist.

Die Registrierung läuft genauso ab, nur erzeugt der Authenticator dabei ein neues Schlüsselpaar und gibt den öffentlichen Schlüssel zurück. Den privaten Schlüssel sieht weder der Server noch der Browser.

## Warum Phishing scheitert

Beim Passwort entscheidet der Nutzer, wo er es eintippt – und eine überzeugende Kopie der Anmeldeseite unter `examp1e-login.com` bekommt das echte Passwort. Ein Code aus der Authenticator-App oder per SMS hilft nicht weiter: Die gefälschte Seite fragt den Code ebenfalls ab und reicht ihn innerhalb der 30 Sekunden, die er gilt, an die echte Seite weiter.

Beim Passkey muss der Nutzer nichts entscheiden, was schiefgehen könnte:

- Der **Browser** schreibt den echten Origin der Seite in das, was der Authenticator signiert. Eine gefälschte Seite kann sich nicht als `app.example.com` ausgeben, denn diesen Wert setzt der Browser ein, nicht die Seite.
- Der **Authenticator** bietet nur Passkeys an, deren Domain zur Seite passt. Auf `examp1e-login.com` hat er schlicht keinen.
- Der **Server** prüft den signierten Origin und die Domain und lehnt alles ab, was nicht für ihn bestimmt war.

Eine nachgemachte Seite erhält keine Antwort, die anderswo funktioniert. Das ist der Hauptgrund, warum Passkeys ein echter Sicherheitsgewinn sind und nicht nur bequemer.

## Warum ein Datenleck viel weniger kostet

Der Server speichert öffentliche Schlüssel, und die nützen einem Angreifer nichts: Mit ihnen lassen sich Signaturen prüfen, aber nicht erstellen. Eine geleakte Passkey-Tabelle bietet nichts, was sich offline knacken oder auf anderen Websites ausprobieren ließe. Und weil jede Website ein eigenes Schlüsselpaar bekommt, gibt es bei Passkeys kein Gegenstück zum überall wiederverwendeten Passwort.

## Besitz und Fingerabdruck: zwei Faktoren in einem Schritt

Ein Passkey belegt zweierlei: Der Nutzer hat das Gerät (Besitz), und er hat es entsperrt (mit Fingerabdruck oder Gesicht, oder mit einer PIN, die er kennt). Deshalb kann ein Passkey allein „Passwort plus zweiter Faktor“ ersetzen. Der Server sollte das allerdings auch verlangen: Er fordert **Nutzerverifikation** an (`userVerification: 'required'`) und lehnt Antworten ab, bei denen der Authenticator den Nutzer nicht geprüft hat. Sonst würde ein Sicherheitsschlüssel ohne PIN jeden anmelden, der ihn in der Hand hält.

## Passkeys im Autofill des Browsers

Nutzer müssen keinen Knopf „Mit Passkey anmelden“ suchen. Der Browser kann die Passkeys des Nutzers im Autofill-Menü des E-Mail-Felds anbieten, neben gespeicherten Passwörtern. Das nennt sich *Conditional Mediation*. Das Feld bekommt dafür das Token `webauthn` im Attribut `autocomplete`:

```html
<input type="email" name="email" autocomplete="username webauthn" />
```

und die Seite startet eine Passkey-Anfrage, die wartet, bis der Nutzer im Menü einen Passkey auswählt:

```js
if (await PublicKeyCredential.isConditionalMediationAvailable?.()) {
  const credential = await navigator.credentials.get({
    mediation: 'conditional',
    publicKey: {
      challenge, // Zufallsbytes vom Server, nur einmal gültig
      rpId: 'example.com',
      userVerification: 'required',
    },
  });
  // credential.response an den Server schicken: Er prüft die Signatur und meldet den Nutzer an.
}
```

Weil diese Passkeys *auffindbar* sind (sie tragen die ID des Nutzers), muss der Nutzer seine Adresse nicht zuerst eingeben – und die Anmeldung verrät nicht, ob zu einer Adresse ein Konto existiert.

## Worauf der Server achten muss

Die Kryptografie übernehmen Browser und Authenticator. Für den Server bleibt Buchführung – und genau dort passieren die Fehler:

- **Jede Challenge nur einmal verwenden.** Sie sollte kurzlebig sein (wenige Minuten), an ihren Zweck gebunden (Anmeldung, Passkey hinzufügen) und gelöscht werden, sobald eine Antwort kommt. Eine doppelt gesendete Antwort darf nur einmal anmelden.
- **Origin und Domain** gegen die eigene Liste prüfen. Nicht dem vertrauen, was die Seite oder die Anfrage über sich selbst behauptet.
- **Die Relying-Party-ID bewusst wählen.** Ein Passkey für `app.example.com` funktioniert nur dort, einer für `example.com` auf allen Subdomains. Wer die Domain später ändert, macht alle bestehenden Passkeys unbrauchbar.
- **Vor dem Hinzufügen erneut anmelden lassen.** Eine übernommene Sitzung – ein gestohlenes Cookie, ein offen gelassener Browser – darf dem Angreifer keinen eigenen Passkey verschaffen, der die Sitzung überdauert.
- **Den letzten Zugang nicht entfernen lassen.** Wer seinen einzigen Passkey löscht oder das Smartphone verliert, auf dem er lag, braucht einen anderen Weg hinein – oder einen Admin, der die Anmeldung zurücksetzt, nachdem er geprüft hat, wer da fragt.
- **Dem Passwortmanager melden, wenn ein Passkey weg ist.** Browser, die die WebAuthn Signal API unterstützen, lassen sich informieren, dass es einen Zugangsschlüssel nicht mehr gibt, und bieten ihn dann nicht mehr an.
- **Den Signaturzähler** von Sicherheitsschlüsseln prüfen: Ein Authenticator mit Zähler muss jedes Mal einen höheren Wert senden. Synchronisierte Passkeys senden 0.

## Passkeys allein oder als zweiter Faktor

Für Passkeys müssen Sie Passwörter nicht abschaffen. Zwei verbreitete Varianten:

- **Passkeys als Anmeldemethode:** Nutzer registrieren sich direkt mit einem Passkey oder per E-Mail, Google oder GitHub und fügen einen hinzu – und melden sich danach allein damit an.
- **Passkeys als zweiter Faktor:** Nutzer melden sich wie bisher mit Passwort an, und der Server fragt danach einen Passkey ab. Anders als ein Code aus der App oder per SMS ist auch dieser zweite Schritt phishing-resistent.

## Passkeys mit madAuth einbauen

[madAuth](/) ist ein quelloffener Authentifizierungsserver, den Sie selbst betreiben, mit einem Anmeldedialog, der in jedem Framework funktioniert. Er setzt die Regeln oben um: Nutzerverifikation ist Pflicht, jede Challenge zählt einmal, ein Passkey lässt sich nur innerhalb von zehn Minuten nach der Anmeldung hinzufügen, der letzte Zugang lässt sich nicht entfernen, und entfernte Passkeys werden dem Browser gemeldet. In der Web-App sind Passkeys ein weiterer Provider:

```ts
import { Madauth, Password, Passkey } from '@madauth/web';

Madauth.initialize({ providers: [new Password(), new Passkey()] });

signInButton.onclick = () => Madauth.signIn(); // der Dialog, mit Passkeys im Autofill des E-Mail-Felds
addPasskeyButton.onclick = () => Madauth.setUpPasskey(); // für angemeldete Nutzer
```

Ob Passkeys allein anmelden oder nur zweiter Faktor sind, legt ein Admin im laufenden Betrieb fest; `PASSKEY_RP_ID` bestimmt die Domain, zu der die Passkeys gehören. Nutzer können sich auch allein mit einem Passkey registrieren: madAuth bestätigt zuerst ihre Adresse per E-Mail, dann wird der Passkey angelegt. Die Details stehen in den [Sicherheitshinweisen zu Passkeys](https://github.com/inouiw/madAuth/blob/main/docs/passkey-security.md) (englisch), und in der [Demo](/demo/) können Sie einen Passkey anlegen und sich damit anmelden.

## Zusammenfassung

- Ein Passkey ist ein Schlüsselpaar pro Website: Der private Schlüssel bleibt beim Nutzer, der Server speichert nur den öffentlichen.
- Der Browser signiert den echten Origin in jede Antwort ein – Phishing-Seiten bekommen nichts Brauchbares.
- Eine geleakte Datenbank mit öffentlichen Schlüsseln ist für Angreifer wertlos.
- Mit verpflichtender Nutzerverifikation zählt eine Passkey-Anmeldung als zwei Faktoren.
- Die Aufgabe des Servers ist Buchführung: einmalige Challenges, Origin-Prüfung, eine bewusst gewählte Domain, erneute Anmeldung und ein Weg zurück ins Konto.

Passkeys passen gut zur Google-Anmeldung. Wie die Abfrage „Weiter als …“ heute funktioniert, erklärt [Google One Tap und FedCM 2026](/posts/google-one-tap-und-fedcm/).
