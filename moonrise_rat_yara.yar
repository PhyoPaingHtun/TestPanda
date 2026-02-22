/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2026-02-22
   Identifier: moonrise
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule moonrise {
   meta:
      description = "moonrise - file moonrise.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-02-22"
      hash1 = "ed5471d42bef6b32253e9c1aba49b01b8282fd096ad0957abcf1a1e27e8f7551"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625BlockInput re-enable failed: %vCLIE" ascii
      $x2 = " to unallocated span37252902984619140625AddFontMemResourceExArabic Standard TimeAzores Standard TimeCertFindChainInStoreCertOpen" ascii
      $x3 = "0123456789abcdefghijklmnopqrstuvwxyz44408920985006261616945266723632812553f4f898-d10b-4d0d-b82d-fca6dff5c53cGo pointer stored in" ascii
      $x4 = "TYASr5UV6HEcXatwdFQfmLVUqQQQMUxHLSVirtualQuery for stack base failed^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$^[LM3][a-km-zA-HJ-NP-Z1-9]" ascii
      $x5 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x6 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x7 = "Bidi_ControlCIDR addressCONTINUATIONCfgMgr32.dllChooseColorWCoCreateGuidContent TypeContent-TypeCookie.ValueCreateBitmapCreateEv" ascii
      $x8 = "addressesatomicor8bad indirbad prunebus errorchan sendcmd_errorcommandIdcomplex64connectexcopystackctxt != 0d.nx != 0debugLockem" ascii
      $x9 = " to non-Go memory , locked to thread298023223876953125: day out of rangeAddFontResourceExWArab Standard TimeCM_MapCrToWin32ErrCa" ascii
      $x10 = "non-IPv4 addressnon-IPv6 addressobject is remoteprotection_errorproxy-connectionread_frame_otherreflect mismatchregexp: Compile(" ascii
      $x11 = "entersyscallexit status explorer.exefun_shutdowngcBitsArenasgcpacertracegetaddrinfowharddecommithost is downhttp2debug=1http2deb" ascii
      $x12 = "IP addressIsValidSidKeep-AliveKharoshthiLoadImageWLocalAllocLockFileExLogin DataManichaeanMessage-IdMicrophoneMoveWindowNo Conte" ascii
      $x13 = " is unavailable()<>@,;:\\\"/[]?=,M3.2.0,M11.1.00601021504Z0700476837158203125: cannot parse <invalid Value>ASCII_Hex_DigitAccept" ascii
      $x14 = " MB,  and  cnt= max= ms,  ptr  tab= top=%d GB%s %q%s*%d%s=%s&#34;&#39;&amp;*.ldb*.log+0330+0430+0530+0545+0630+0845+1030+1245+13" ascii
      $x15 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vwebsocket: bad handshakewebsocke" ascii
      $x16 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii
      $x17 = "del /f /q \"%%~f0\"http2: Transport closing idle conn %p (forSingleUse=%v, maxStream=%v)tls: handshake message of length %d byte" ascii
      $x18 = "flate: internal error: frame_goaway_has_streamframe_headers_pad_shortframe_rststream_bad_lengarbage collection scangcDrain phase" ascii
      $x19 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionwebsocket: flateRead" ascii
      $x20 = "value=abortedalt -> any -> avx512fbrowsercamerascharsetchunkedconnectconsolecpuprofderiveddiscordenabledexpiresfloat32float64for" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      ( pe.imphash() == "9cbefe68f395e67356e2a5d8d1b285c0" or 1 of ($x*) )
}

/* Super Rules ------------------------------------------------------------- */

