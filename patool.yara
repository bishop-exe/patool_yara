rule zip : zip
{
   meta:
      description = "File type signature for basic ZIP files."

   strings:
      $pk = { 50 4B 03 04 }

   condition:
      $pk at 0
}
rule ft_tar
{
   meta:
    description = "Signature to detect on TAR archive files"

   strings:
      $magic = { 75 73 74 61 72 }

   condition:
      $magic at 257
}

rule _7z: _7z
{
    meta:
    description = "Trigger on magic of 7z compressed files"

    strings:
        $a = {37 7A BC AF 27 1C}

    condition:
       $a at 0
}

rule rar: rar
{
    meta:
    description = "Signature to detect on RAR archive files and cbr"

    strings:
        $a = {52 61 72 21 1A 07 00}
        $b = {52 61 72 21 1A 07 01 00}

    condition:
    $a at 0 or $b at 0
}

rule tar: tar
{
    meta:
    description ="Signature to detect on TAR archive files"

    strings:
        $a = {75 73 74 61 72 00 30 30}
        $b = {75 73 74 61 72 20 20 00}

    condition:
    $a at 0 or $b at 0
}

rule gzip: gzip
{
    meta:
    description = "Trigger on magic of GZip compressed files"
    strings:
        $a = {1F 8B}
        $b = {1F 8B}

    condition:
    $a at 0 or $b at 0
}
rule bzip2: bzip2
{
    meta:
    description = "Trigger on magic of bZip2 compressed files"
    strings:
        $a = {42 5a}
        $b = {42 5a}

    condition:
    $a at 0 or $b at 0
}
rule ft_cab
{
   meta:
      desc = "File magic for CABs (Microsoft Cabinet Files)"
   strings:
      $cab = { 4D 53 43 46 }

   condition:
      $cab at 0
}
rule flac
{
   meta:
      desc = "File magic for FLACs (Free Lossless Audio Codec file)"
   strings:
      $flac = { 66 4C 61 43 00 00 00 22 }

   condition:
      $flac at 0
}
rule adf
{
   meta:
      desc = "File magic for adf (Amiga disk file)"
   strings:
      $adf = { 44 4F 53 }

   condition:
      $adf at 0
}
rule xz
{
   meta:
      desc = "File magic XZ archive file"
   strings:
      $xz = { FD 37 7A 58 5A 00 }

   condition:
      $xz at 0
}
rule JAR
{
   meta:
      desc = "File magic Jar archive"
   strings:
      $JAR = { 5F 27 A8 89 }

   condition:
      $JAR at 0
}
rule LZH
{
   meta:
      desc = "Compressed tape archive file using LZH (Lempel-Ziv-Huffman) compression"
   strings:
      $a = { 1F 9D }
      $b = { 1F A0 }
   condition:
      $a at 0 or $b at 0
}
rule ARJ
{
   meta:
      desc = "Compressed archive file"
   strings:
      $a = { 60 EA }
   condition:
      $a at 0
}
rule DMS
{
   meta:
      desc = "Amiga DiskMasher compressed archive"
   strings:
      $a = { 44 4D 53 21 }
   condition:
      $a at 0
}
rule ARC
{
   meta:
      desc = "FreeArc compressed file"
   strings:
      $a = { 41 72 43 01 }
      $arc_old = { 1A (02 | 03 | 04 | 08 | 09) }
   condition:
      $a at 0 or $arc_old at 0 
}
rule rzip
{
   meta:
      desc = "rzip compressed file"
   strings:
      $a = { 52 5A 49 50 }
   condition:
      $a at 0
}
rule ape
{
   meta:
      desc = "ape compressed file"
   strings:
      $a = { 4D 41 43 20 }
   condition:
      $a at 0
}
rule ALZ
{
   meta:
      desc = "ALZ compressed file"
   strings:
      $a = { 41 4C 5A }
   condition:
      $a at 0
}
rule AR
{
   meta:
      desc = "AR *.a compressed file"
   strings:
      $a = { 21 3C 61 72 63 68 3E }
   condition:
      $a at 0
}
rule RPM
{
   meta:
      desc = "RedHat Package Manager"
   strings:
      $a = { ED AB EE DB }
   condition:
      $a at 0
}
rule ISO
{
   meta:
      desc = "ISO-9660 CD Disc Image"
   strings:
      $a = { 43 44 30 30 31 }
   condition:
      $a
}
rule ZOO
{
   meta:
      desc = "ZOO compressed archive"
   strings:
      $a = { 5A 4F 4F 20 }
   condition:
      $a at 0
}
rule VHD
{
   meta:
      desc = "	Virtual PC HD image"
   strings:
      $a = { 63 6F 6E 65 63 74 69 78 }
   condition:
      $a at 0
}
rule LZO
{
   meta:
      desc = "LZO"
   strings:
      $a = { 4C 5A 4F }
   condition:
      $a  in (0..10)
}
rule LZIP
{
   meta:
      desc = "LZIP"
   strings:
      $a = { 4C 5A 49 50 01}
   condition:
      $a  in (0..10)
}
rule LZMA
{
   meta:
      desc = "LZIP"
   strings:
      $a = { 5d 00 00 80 00 ff ff ff ff ff ff ff ff 00 }
   condition:
      $a at 0
}
rule ACE
{
   meta:
      desc = "ACE"
   strings:
      $a = { 2A 2A 41 43 45 2A 2A }
   condition:
      $a  in (0..10)
}