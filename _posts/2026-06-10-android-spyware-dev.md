---
title: Building Android Malware
date: 2026-06-10
categories: [Development, Write-up]
tags: [android, malware, internship, java, kotlin]
author: Mohamad Helmi
description: "How I built a parental control app that's actually a malware"
---

# Building Android Malware for My First Internship Task

## Intro

First week of internship. I was tasked to demonstrate a malicious APK. No prior Android development experience. Never touched Kotlin. Never wanted to, and after this, I still don't.

The only thing I can do is to vibe coded the whole process. And of course, AI will reject it. So, the easiest angle I could think of was to frame it as a parental control app — it's the same thing, really. A parental control app monitors keystrokes, tracks location, intercepts notifications, reads contacts, and reports back to a remote server. The only difference between that and malware is whether you told the person first. I named it **SafeKid**. Very wholesome.

> 📁 Source code available at [here](https://github.com/helmieus/SafeKid)

---

## Architecture

The system has two parts:

1. **Android APK** — installed on the target device. Runs as a persistent background service, collects data, and sends everything to a remote server.
2. **Discord Bot + Express Server** — the C2. Parents (or whoever) monitor everything from a Discord server. Each event type gets its own channel.

```
[Android Device]  →  POST /data  →  [Express Server :3000]  →  [Discord Channels]
                  ←  GET /commands  ←
```

The bot exposes slash commands for the operator to interact with the device — toggle keystroke logging, request live location, dump contacts, and so on.

![system architecture](/assets/img/posts/2026-06-10-android-spyware-dev/SafeKid_Architecture.png)

---

## Android App

### Features

The APK does six things:

| Feature | Implementation |
|---|---|
| Online status | Heartbeat `POST /data` every 60 seconds |
| Keystroke logging | `AccessibilityService` — captures all text input across every app |
| App activity | `UsageStatsManager` — polls foreground app every 5 seconds |
| Contacts dump | `ContentResolver` — on first install or on-demand |
| Live location | `FusedLocationProviderClient` — every 5 minutes or on-demand |
| Notification intercept | `NotificationListenerService` — captures all incoming notifications |

The app also polls `GET /commands` every 10 seconds to receive instructions from the operator.

![permission wizard](/assets/img/posts/2026-06-10-android-spyware-dev/permission_wizard.jpg)

### The Permissions Problem

This is where Android makes life difficult. Three permissions cannot be granted programmatically — the user has to manually enable them in Settings:

- **Accessibility Service** — required for keystroke capture
- **Notification Listener** — required for notification intercept  
- **Usage Stats** — required for app activity monitoring

So `MainActivity` exists purely as a setup wizard that walks through each permission and provides a button to open the right settings screen. The app has a launcher icon specifically for this — once setup is done, the service runs silently in the background.

### Keeping the Service Alive

Android aggressively kills background services, especially on budget phones running heavily modified OS versions (looking at you, Vivo Funtouch OS). The approach here:

- **Foreground service** with a sticky notification — harder for the OS to kill
- **`BootReceiver`** — auto-starts on device reboot
- **WorkManager watchdog** — reschedules the service every 15 minutes if it gets killed

---

## C2 — Discord Bot

The bot runs on Express and uses Discord.js v14. Each event type is routed to a dedicated channel:

| Event | Channel |
|---|---|
| Heartbeat (online/offline) | `#status` |
| Keystrokes | `#keystrokes` |
| App activity | `#app-activity` |
| Notifications | `#notifications` |
| Location | `#locations` |
| Contacts | `#contacts` |
| Command responses | `#commands` |

Slash commands available to the operator:

```
/status                     — show all registered devices
/keystroke <on|off>         — toggle keystroke logging
/notification <on|off>      — toggle notification monitoring
/location [childId]         — request live GPS location
/contacts [childId]         — dump all contacts
/keylog [childId]           — show last 20 keystrokes
/applog [childId]           — show last 20 apps opened
/notiflog [childId]         — show last 20 notifications
```

Data is persisted in a local `db.json` via lowdb — last 100 events per type.

![Discord server — channel overview](/assets/img/posts/2026-06-10-android-spyware-dev/discord_channel.png)

![Status channel — device online alert](/assets/img/posts/2026-06-10-android-spyware-dev/discord_status.png)

![Keystrokes channel](/assets/img/posts/2026-06-10-android-spyware-dev/keystrokes.png)

![Location channel — Google Maps link](/assets/img/posts/2026-06-10-android-spyware-dev/locations.png)

---

## Issues Along the Way

### CLEARTEXT Traffic Blocked

First sign of life from logcat:

```
java.net.UnknownServiceException: CLEARTEXT communication to 203.106.118.139
not permitted by network security policy
```

Android 9+ blocks plain HTTP by default. Fix is two lines — add `network_security_config.xml` and reference it in the manifest:

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="true"
    ...>
```

### ForegroundServiceStartNotAllowedException

After fixing the network issue, the service crashed immediately on launch:

```
android.app.ForegroundServiceStartNotAllowedException:
Service.startForeground() not allowed due to mAllowStartForeground false
```

Android 12+ restricts foreground services from starting while the app is in the background. The fix was to start the service from `onResume()` in `MainActivity` — user interaction context — rather than from the boot receiver alone.

A secondary bug made this worse: `startForeground()` was being called before `createNotificationChannel()`, meaning the notification channel didn't exist yet when the service tried to post its sticky notification. Reordering the calls in `onCreate()` fixed it.

### No App Icon

The generated manifest had a typo in the launcher intent filter:

```xml
<!-- Wrong -->
<category android:name="android.intent.action.LAUNCHER" />

<!-- Correct -->
<category android:name="android.intent.category.LAUNCHER" />
```

`action` vs `category` — one character difference, no icon on the homescreen.

### Vivo Funtouch OS Battery Optimization

Testing on a Vivo Y35 — Funtouch OS kills background apps very aggressively. Standard fix:

```
Settings → Battery → App Battery Management → SafeKid → No Restrictions
```

The foreground service + WorkManager watchdog combo handles the rest.

![Logcat — service running confirmation](/assets/img/posts/2026-06-10-android-spyware-dev/logcat.png)

---

## Future Works

The current implementation covers the basics, but there's a lot of room to make this more capable — or more dangerous, depending on who's asking.

### HTTPS / Encrypted Transport

Right now all traffic between the device and the server is plain HTTP. Anyone on the same network can intercept the data stream — keystrokes, location, contacts, all of it in cleartext. The proper fix is to put the Express server behind an Nginx reverse proxy with a TLS certificate (Let's Encrypt works fine for this) and update `config.json` to use `https://`. This also removes the need for the `cleartextTrafficPermitted` hack in the manifest.

### Screen Recording / Screenshots

`MediaProjection` API allows screen capture without root. A periodic screenshot or short screen recording sent back to the server would give a much more complete picture of what's happening on the device compared to app names and keystrokes alone. The tradeoff is file size — images and video need a different upload mechanism than the current JSON payloads.

### Call Log & SMS Interception

The `READ_CALL_LOG` and `READ_SMS` permissions are standard runtime permissions — no special settings screen required. Adding these would expose full call history (number, duration, direction) and all SMS messages. Particularly relevant for monitoring communication that doesn't go through internet-based apps.

### Camera & Microphone Access

`CameraManager` and `AudioRecord` can be triggered silently from a background service. A remote command to capture a photo or a short audio clip is technically straightforward — the main constraint is Android's privacy indicators (the green dot in the status bar on Android 12+) which will show whenever the mic or camera is active. Harder to do silently on modern Android.

### Geofencing Alerts

Instead of passively reporting location every 5 minutes, geofencing would let the operator define a boundary and receive an alert only when the device crosses it. Google's `GeofencingClient` handles this natively and is more battery-efficient than constant polling. Useful for actual parental control use cases — get notified when the kid leaves school, not just every 5 minutes.

### Multi-Device Support

The current architecture supports multiple `childId` values in theory, but the Discord bot UX around it is rough — you have to manually specify `childId` in every command if there's more than one device. A proper multi-device flow would include device registration, a `#status` dashboard that updates in real-time, and per-device command routing without needing to type the ID every time.

### Persistence Without User Interaction

The current setup requires the parent to physically open the app on the child's device to complete the permission wizard. A more complete implementation would explore device policy controller (DPC) APIs or MDM-style enrollment, which can push configurations and grant certain permissions silently — though this requires the device to be enrolled in a managed profile, which is a much more involved setup process.

### Replace Discord with a Proper Dashboard

Discord works surprisingly well as a lightweight C2, but it has real limitations — message rate limits, no search across event history, no data visualization, and it's tied to a third-party platform. A proper web dashboard with a database backend, charts for app usage patterns, a location history map, and keyword alerts on keystrokes would be a significant improvement for any serious deployment.

---

## Key Takeaways

- **The line between parental control and spyware is consent, not code** — the same `AccessibilityService` that logs keystrokes for a parent is the same one used in banking trojans. The implementation is identical.
- **Android's security model is actually pretty solid** — CLEARTEXT blocking, foreground service restrictions, and manual permission grants for sensitive APIs all exist for good reason. They made this annoying to build.
- **Budget Android phones are a nightmare for persistent services** — manufacturer OS modifications aggressively kill background processes in ways stock Android doesn't.
- **Discord makes a surprisingly functional C2** — slash commands, embeds, per-channel routing. Works well for a lightweight monitoring setup.
- **I still don't want to touch Android development again.**