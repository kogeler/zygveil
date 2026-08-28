<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# Third-Party Sources

The ZygVeil host is built from source inside the pinned repository builder. It has no runtime
dependency on Xposed, LSPosed, EdXposed, or Riru.

| Source | Revision | License | Use |
|---|---|---|---|
| Magisk Zygisk module sample | `8ce26128f81baaed0b969aaf7f52f886b61af4ab` | 0BSD | Zygisk API v5 header |
| Android NDK libc++ | `29.0.14206865` | Apache-2.0 WITH LLVM-exception | Statically embedded C++ runtime |
| LSPlant | `61e10e51eb99dca00dd873f48c28a674dd2b4c4c` | LGPL-3.0-or-later | ART Java-method hook engine |
| DexBuilder | `ac7fb2230954ee311808bad469b0db501f31bfb8` | LGPL-3.0-or-later | LSPlant generated callback DEX |
| parallel-hashmap | `0cd57d29a959256ed66b2afdd1009928fc625d09` | Apache-2.0 | DexBuilder container dependency |
| ShadowHook | `854c775c2c3676e57a0f383597ebf420b5204161` (`2.0.1`) | MIT | arm64 inline hook and `libart` symbol resolver |

Archive SHA-256 values are enforced in `containers/builder/Containerfile`. LSPlant is a standalone
library from the LSPosed organization; no LSPosed service, framework, protocol, scope, or runtime
code is used by the supported host.
