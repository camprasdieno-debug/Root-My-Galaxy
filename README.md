# Root My Galaxy

<img width="108" height="108" alt="sprout_icon_108" src="https://github.com/user-attachments/assets/2ba0e360-0876-489c-b256-f75df7589785" />


Root My Galaxy is a one-click installer for explicitly
supported Samsung model and kernel combinations. The application itself is kept separate
from device offsets, native exploit payloads, and KernelSU build artifacts.


[Latest release](https://github.com/Daubfy/Root-My-Galaxy/releases)

The device feed and native payloads are maintained in
[IonStack-S22U](https://github.com/Daubfy/IonStack-S22U/tree/main/artifacts).

## Application


<img width="200" alt="Screenshot_20260829_210128_Root My Galaxy" src="https://github.com/user-attachments/assets/934d2478-a364-425c-ace7-29481aa9e488" />
<img width="200" alt="Screenshot_20260830_105035_Root My Galaxy" src="https://github.com/user-attachments/assets/67c64104-fa6d-4c2a-b364-d671ac54e0b7" />
<img width="200" alt="Screenshot_20260830_105044_Root My Galaxy" src="https://github.com/user-attachments/assets/a25c72b3-b8af-442f-9a6d-1679ab8c356e" />


The app selects a payload whose model list and three-part kernel version match
the phone. For example, `6.6.98-android15-8-...` matches `6.6.98`. Advanced
mode filters the catalog by both values and allows manual selection with model
and kernel-version warnings.

## Initial Setup

- Download the payload for your device [here](https://github.com/Daubfy/IonStack-S22U/tree/main/artifacts)

- Download the [KernelSU Next module](https://github.com/sarabpal-dev/KernelSU-Next/releases/download/v3.3.0-android12-5.10/kernelsu-android12-5.10.ko)

You should now have something like this:

<img width="506" height="336" alt="image" src="https://github.com/user-attachments/assets/f6ecc57b-473d-4c0f-a476-10ca2ce487e2" />

- Push the payload and the KernelSU module to your device:

```sh
adb push cve-2026-43499 /data/local/tmp/cve-2026-43499
adb push cve-2026-43499-root /data/local/tmp/cve-2026-43499-root
adb push cve-exp32 /data/local/tmp/cve-exp32
adb push kernelsu-android12-5.10.ko /data/local/tmp/kernelsu-android12-5.10.ko
adb shell chmod 755 /data/local/tmp/cve-2026-43499 /data/local/tmp/cve-2026-43499-root /data/local/tmp/cve-exp32
```



## Build

Requirements:

- Android Studio JBR 21
- Android SDK 37
- Android NDK 29 or newer
- CMake 3.22.1

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat :app:assembleDebug
```

Output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Use only on devices you own or are explicitly authorized to test.
