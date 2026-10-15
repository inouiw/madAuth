---
slug: google-one-tap-und-fedcm
title: Google One Tap und FedCM 2026: Was sich geändert hat – und was nicht
seoTitle: Google One Tap & FedCM 2026: Was sich ändert
description: Google One Tap läuft über die FedCM-API des Browsers. Was das bedeutet, seit Chrome Drittanbieter-Cookies behält, und was Ihr Server am ID-Token prüfen muss.
published: 2026-10-15
---

Google One Tap ist die kleine Abfrage „Weiter als Jan“, die Nutzer mit einem Klick über ihr Google-Konto anmeldet, ohne Umleitung zu Google. Jahrelang funktionierte das über ein iframe von `accounts.google.com`, das Googles Cookies las – auf Ihrer Website sind das Drittanbieter-Cookies. In Chrome läuft One Tap inzwischen über eine Browser-API: **FedCM**, die Federated Credential Management API.

Dann verkündete Google 2025, dass Chrome die Drittanbieter-Cookies doch behält. Ist FedCM damit noch wichtig? Ja – dieser Artikel erklärt, warum, was sich für Entwickler geändert hat und was Ihr Server weiterhin prüfen muss.

## Was FedCM ist

FedCM ist eine Browser-API für „Anmelden mit einem Identitätsanbieter“. Statt dass das iframe des Anbieters die Abfrage zeichnet, zeichnet sie der **Browser** selbst, und er spricht selbst mit dem Anbieter:

1. Ihre Seite bittet den Browser um einen Identitätsnachweis von einem Anbieter, hier Google.
2. Der Browser lädt die Konfiguration des Anbieters und fragt, welche Konten angemeldet sind. Der Anbieter erfährt dabei nicht, welche Website fragt.
3. Der Browser zeigt seinen eigenen Dialog „Weiter als …“.
4. Erst wenn der Nutzer zustimmt, fordert der Browser beim Anbieter ein Token für diese Website und das gewählte Konto an und gibt es an die Seite weiter.

Darunter steckt ein Aufruf wie dieser (Googles Bibliothek erledigt ihn für Sie):

```js
const credential = await navigator.credentials.get({
  identity: { providers: [{ configURL: 'https://idp.example/fedcm.json', clientId: 'ihre-client-id' }] },
});
```

Der Sinn dahinter: Der Identitätsanbieter kann nicht verfolgen, welche Websites ein Nutzer besucht, bevor dieser sich für die Anmeldung entscheidet – und der Ablauf braucht keine Drittanbieter-Cookies.

## Die Wende bei den Cookies

FedCM wurde für ein Web ohne Drittanbieter-Cookies gebaut. Chrome wollte sie abschaffen, und Google Identity Services begann 2024, One Tap in Chrome auf FedCM umzustellen, um darauf vorbereitet zu sein. Im April 2025 gab Google diesen Plan auf: Chrome behält die Drittanbieter-Cookies und führt keine neue Cookie-Abfrage ein. Im Herbst 2025 ging Google noch weiter und stellte die meisten Privacy-Sandbox-APIs ein, die Cookies ersetzen sollten.

FedCM gehörte nicht dazu. Google behält es, zusammen mit CHIPS und Private State Tokens. Die Umstellung von One Tap in Chrome bleibt also bestehen – und zwei Gründe machen sie zu mehr als einem Chrome-Detail:

- **Safari und Firefox blockieren Drittanbieter-Cookies ohnehin standardmäßig**, mit Intelligent Tracking Prevention und dem vollständigen Cookie-Schutz. Eine Anmeldung, die auf sie angewiesen ist, scheitert bei einem großen Teil der Nutzer – egal, was Chrome tut.
- **Der eigene Dialog des Browsers** sieht überall gleich aus, kann von der Seite nicht überdeckt werden und begegnet Nutzern zunehmend auch auf anderen Websites.

Kurz: Es gibt kein Zurück. Bauen Sie für FedCM.

## Was sich für Entwickler geändert hat

Bei den meisten Websites hat Googles Bibliothek die Umstellung ohne Codeänderung erledigt. Einiges verhält sich aber anders, und das erklärt die meisten Meldungen à la „One Tap erscheint nicht mehr“:

- **Die Position ist nicht mehr wählbar.** Der Browser platziert seinen Dialog; Einstellungen, die früher Googles iframe verschoben, wirken nicht mehr.
- **Weniger Status-Callbacks.** Die meisten der alten Benachrichtigungen darüber, warum die Abfrage nicht angezeigt oder übersprungen wurde, liefern keinen Grund mehr. Bauen Sie keine Logik darauf.
- **iframes brauchen eine Erlaubnis.** Läuft One Tap oder der Button in einem iframe einer anderen Origin, braucht jedes übergeordnete iframe `allow="identity-credentials-get"`.
- **Die Sperrzeit verwaltet der Browser.** Wer die Abfrage schließt, sieht sie eine Weile nicht mehr, und die Pause wird jedes Mal länger. Nutzer können außerdem in den Website-Einstellungen von Chrome die „Anmeldung über Drittanbieter“ abschalten. Zeigen Sie deshalb immer auch einen sichtbaren Google-Button.
- **Auch der Button kann FedCM nutzen.** Mit `use_fedcm_for_button: true` öffnet der Google-Button den Dialog des Browsers statt eines Pop-up-Fensters.
- **Safari und Firefox bekommen eine eigene Oberfläche.** Mit `itp_support: true` zeigt Googles Bibliothek in Browsern mit Tracking-Schutz eine verbesserte One-Tap-Variante.

Eine typische Einrichtung mit Google Identity Services:

```js
google.accounts.id.initialize({
  client_id: 'ihre-client-id.apps.googleusercontent.com',
  nonce, // vom Server, siehe unten
  callback: ({ credential }) => sendToServer(credential),
  use_fedcm_for_button: true,
  itp_support: true,
});
google.accounts.id.prompt(); // One Tap
google.accounts.id.renderButton(container, { text: 'continue_with' }); // der Fallback
```

Für die Entwicklung tragen Sie in der Google Cloud Console unter **Autorisierte JavaScript-Quellen** sowohl `http://localhost:<port>` als auch `http://localhost` ein.

## Was der Server weiterhin prüfen muss

FedCM ändert, wie die Abfrage erscheint, nicht, was dabei herauskommt: Ihre Seite erhält ein **Google-ID-Token**, ein signiertes JWT, und gibt es an Ihren Server weiter. Der Server darf ihm erst trauen, wenn er geprüft hat:

- die **Signatur**, mit Googles veröffentlichten Schlüsseln,
- den **Aussteller** (`accounts.google.com` oder `https://accounts.google.com`),
- die **Zielgruppe** (`aud`): Ihre eigene Client-ID, damit ein Token, das für eine andere App ausgestellt wurde, niemanden bei Ihnen anmeldet,
- den **Ablaufzeitpunkt**,
- die **Nonce**: Ihr Server erzeugt pro Anmeldung eine neue und akzeptiert sie genau einmal, damit ein abgefangenes Token nicht wiederverwendet werden kann,
- **`email_verified`**, bevor Sie die Adresse für irgendetwas verwenden.

Und erkennen Sie den Nutzer an Googles **`sub`**, nicht an der E-Mail-Adresse: Ein Google-Konto behält sein `sub`, auch wenn sich die Adresse ändert.

Hat eine App mehrere Anmeldemethoden, gilt noch etwas: Eine Google-Anmeldung mit der Adresse eines bestehenden Passwort-Kontos darf nicht einfach in dieses Konto führen. Wer ein Google-Konto mit dieser Adresse kontrolliert, käme sonst am Passwort und an jedem zweiten Faktor vorbei.

## Die Alternative: der Redirect-Ablauf

One Tap und FedCM laufen im Browser und brauchen Googles Skript auf Ihrer Seite. Der klassische OAuth-Redirect funktioniert überall: Der Browser geht zu Google, der Nutzer stimmt zu, und Google schickt ihn mit einem Code an Ihren Server zurück, der den Code gegen das Token tauscht. Das braucht ein Client-Secret und einen Umweg über Google, aber kein fremdes Skript und keine Browserunterstützung. Viele Apps bieten One Tap für die schnelle Anmeldung und behalten den Redirect für alle anderen Fälle.

## Google-Anmeldung mit madAuth

[madAuth](/) ist ein quelloffener Authentifizierungsserver, den Sie selbst betreiben. Er kennt beide Google-Abläufe: `GoogleFedcm` nutzt One Tap und FedCM mit den Einstellungen oben, `GoogleRedirect` den serverseitigen Redirect. Der Server prüft das ID-Token wie beschrieben – Signatur, Aussteller, Zielgruppe, Ablauf, Nonce und eine bestätigte Adresse – und lehnt eine Google-Anmeldung ab, die ein Konto übernehmen würde, das sich auf anderem Weg anmeldet.

```ts
import { Madauth, GoogleFedcm, Passkey } from '@madauth/web';

// One Tap beim Laden der Seite, wenn niemand angemeldet ist; Googles Button im Anmeldedialog als Fallback.
Madauth.initialize({ providers: [new GoogleFedcm(), new Passkey()] });
signInButton.onclick = () => Madauth.signIn();
```

Der Server braucht `GOOGLE_CLIENT_ID`, für den Redirect zusätzlich `GOOGLE_CLIENT_SECRET`. Mit `new GoogleFedcm({ autoPrompt: false })` erscheint Google nur im Dialog. Die Einrichtung beschreibt die [Server-Dokumentation](https://github.com/inouiw/madAuth/blob/main/docs/server.md#google-cloud-console-setup) (englisch), und die [Demo](/demo/) schaltet zwischen beiden Abläufen um.

## Zusammenfassung

- In Chrome läuft One Tap über FedCM: Der Browser zeichnet die Abfrage, und Google erfährt erst von Ihrer Website, wenn der Nutzer zustimmt.
- Chrome behält die Drittanbieter-Cookies, aber FedCM bleibt – und Safari und Firefox blockieren Drittanbieter-Cookies ohnehin.
- Rechnen Sie mit einer vom Browser platzierten Abfrage, weniger Status-Callbacks, einer Sperrzeit und iframe-Berechtigungen; behalten Sie einen sichtbaren Google-Button.
- Die Aufgabe des Servers bleibt dieselbe: das ID-Token vollständig prüfen, die Nonce nur einmal akzeptieren, Nutzer an `sub` erkennen.

Die Google-Anmeldung passt gut zu Passkeys. Wie sie funktionieren und warum sie Phishing verhindern, erklärt [Passkeys erklärt](/posts/passkeys-erklaert/).
