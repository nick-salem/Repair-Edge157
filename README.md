# Repair-Edge157

Fix for Microsoft Edge or Microsoft Edge WebView2 Runtime failing to start with:

> The application was unable to start correctly (0xc000007b). Click OK to close the application.

Seen in November 2026 after Edge / WebView2 updated to **157.0.4341.42**.

## What's going on

On affected PCs, the new version folder

- `C:\Program Files (x86)\Microsoft\Edge\Application\157.0.4341.42`
- `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\157.0.4341.42`

is filled mostly with **32-bit (x86)** program files, while Windows has the product registered
and launches it as **64-bit (x64)**. The 64-bit launcher loads a 32-bit `msedge.dll`, and Windows
stops it with `0xc000007b` (STATUS_INVALID_IMAGE_FORMAT).

A healthy x64 install has about 2 x86 files in that folder. A broken one has 25 to 40.

Across the PCs we manage, broken **WebView2** is far more common than broken Edge. When WebView2 is broken,
Edge itself may open fine, but apps built on WebView2 fail or show blank windows: new Outlook, Teams,
Microsoft 365 Copilot, Adobe Acrobat, ChatGPT desktop, Widgets and others.

Not every PC on 157.0.4341.42 is affected, and Microsoft has not listed it as a known issue yet
(see [Microsoft Edge known issues](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-known-issues)).

## Why a normal repair can fail

Settings > Apps > Microsoft Edge > Repair, or an in-place MSI reinstall, can leave the bad files in place
because Windows Installer skips files whose version number already matches. WebView2 repairs also fail while
Teams, Outlook or other apps hold the folder open.

## What the script does

For Edge and WebView2 separately:

1. **Checks** the newest version folder by reading the PE header of every `.dll` / `.exe`.
2. If it's broken, **downloads** the current x64 installer straight from Microsoft and
   **verifies** its Authenticode signature (must be valid and signed by Microsoft Corporation).
3. **Closes** the processes using that folder (Edge, Teams, Outlook and other WebView2 apps).
4. **Renames** the bad folder to `<version>.x86bad`. Nothing is deleted, so you can roll back.
5. **Installs** fresh, re-checks, and test-launches Edge headless with a throwaway profile.

Healthy installs are never touched. Nothing is sent anywhere except the downloads from Microsoft.

## Usage

Check only (no admin needed, changes nothing):

```powershell
powershell -ExecutionPolicy Bypass -File .\Repair-Edge157.ps1 -CheckOnly
```

Repair (run as Administrator, or as SYSTEM from your RMM):

```powershell
powershell -ExecutionPolicy Bypass -File .\Repair-Edge157.ps1
```

Exit codes: `0` healthy or fixed, `1` broken (check only) or still broken after repair, `2` not admin / not 64-bit Windows.
Log: `%windir%\Temp\Repair-Edge157\`.

Heads up: a repair closes Edge, Teams, Outlook and any other app using WebView2 on that PC.
Run it when the user can spare a minute, or tell them first.

## If it comes back

Some admins report the error returning after a fix. Run the script with `-CheckOnly` on a schedule
and repair again if it reports broken.

## Disclaimer

Provided as is, without warranty, under the MIT License. Test on one PC before deploying widely.

Published by [Boston Managed IT](https://bostonmit.com) and [SWFIT](https://swfit.io).
If you're a client and Edge or your apps won't open, open a ticket and we'll fix it remotely.
