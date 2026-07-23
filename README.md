```
____              ___                             ___
`Mb(      db      )d'                 68b         `MM
 YM.     ,PM.     ,P                  Y89   /      MM
 `Mb     d'Mb     d' ___  __    ___   ___  /M      MM  __
  YM.   ,P YM.   ,P  `MM 6MM  6MMMMb  `MM /MMMMM   MM 6MMb
  `Mb   d' `Mb   d'   MM69 " 8M'  `Mb  MM  MM      MMM9 `Mb
   YM. ,P   YM. ,P    MM'        ,oMM  MM  MM      MM'   MM
   `Mb d'   `Mb d'    MM     ,6MM9'MM  MM  MM      MM    MM
    YM,P     YM,P     MM     MM'   MM  MM  MM      MM    MM
    `MM'     `MM'     MM     MM.  ,MM  MM  YM.  ,  MM    MM
     YP       YP     _MM_    `YMMM9'Yb_MM_  YMMM9 _MM_  _MM_
```

Share one keyboard and mouse across several machines on a local network, with a
shared clipboard. Push the cursor off the edge of one screen and it arrives on
the next.

## Quick start

Install on each machine:

```sh
cargo install --locked wraith
```

Pair two of them. On the first:

```sh
wraith pair
```

On the second, with the code the first printed:

```sh
wraith pair --join desktop --code 418 902
```

Pairing asks which side the other machine sits on, or takes `--side right`, and
writes the desk on both. It happens once.

Run a session on each:

```sh
wraith serve
```

The cursor crosses when you push into an edge. Machines find each other on the
network, so there is no address to configure and nothing to change when a DHCP
lease does.

## Overview

`wraith serve` captures local input, forwards it over an encrypted link, and
injects it on whichever machine holds the cursor. It is headless.

The clipboard is shared, so you can copy and paste across machines. Text only
for now.

Machines are peers. Each one listens and dials, so there is no server to
nominate.

Pairing is the only route into the trust store. Two machines exchange a
six-digit code over SPAKE2, keep each other's Ed25519 identity, and thereafter
speak QUIC with mutual TLS 1.3 pinned to those keys.

## Recovering a held key

```sh
wraith unstick
```

Releases every modifier on this machine, whatever put them down, then asks the
display server whether it worked. `--all` sweeps every key rather than the
modifiers; it costs no more time, and is not the default because it also
releases whatever you are holding at that moment.

A session releases what it holds through nine layers, five of which need nothing
from the machine that sent the input. One case defeats all of them: `SIGKILL`
skips every destructor, and X11 XTEST has no notion of releasing a dead client's
keys. `unstick` is a separate process for exactly that, and needs no
configuration and no running session.

## Platform support

|                              | Capture | Inject | Clipboard |
|------------------------------|:-------:|:------:|:---------:|
| Linux, X11                   |   yes   |  yes   |    yes    |
| macOS                        |   yes   |  yes   |    yes    |
| Linux, wlroots and Hyprland  |    -    |  yes   |     -     |
| Linux, GNOME and KDE (libei) |    -    |   -    |     -     |
| Windows                      |    -    |   -    |     -     |

Inject without capture means a machine can receive the cursor but never send it.
The wlroots backend is written and has hardware tests, but no machine of that
kind has run them.

Installing needs no system libraries. The backends are pure Rust, so a toolchain
and a C compiler are the whole of it.

## Diagnostics

```sh
wraith status              # what a running session is doing
wraith probe               # what Wraith makes of this machine
wraith watch               # print every crossing as it happens
wraith bench               # what Wraith adds to input latency
wraith capture --suppress  # print local input, and withhold it while doing so
```

`wraith bench` measures against a budget from the HCI literature: p50 at or
under 2ms, p99 at or under 8ms.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
