# patool Yara Rules


I wrote up some yara rules to interface with patool for auto extraction and thought that it might be handy for someone.  

To quote patool's readme
>patool is a portable command line archive file manager

>patool supports 7z (.7z, .cb7), ACE (.ace, .cba), ADF (.adf), ALZIP (.alz), APE (.ape), AR (.a), ARC (.arc), ARJ (.arj), BZIP2 (.bz2), CAB (.cab), COMPRESS (.Z), CPIO (.cpio), DEB (.deb), DMS (.dms), FLAC (.flac), GZIP (.gz), ISO (.iso), LRZIP (.lrz), LZH (.lha, .lzh), LZIP (.lz), LZMA (.lzma), LZOP (.lzo), RPM (.rpm), RAR (.rar, .cbr), RZIP (.rz), SHN (.shn), TAR (.tar, .cbt), XZ (.xz), ZIP (.zip, .jar, .cbz) and ZOO (.zoo) archive formats. It relies on helper applications to handle those archive formats (for example bzip2 for BZIP2 archives).

The rules are specifically aimed towards the magic number and doesnt do any thing malware/forensic specific.

## patool Git
[https://github.com/wummel/patool](https://github.com/wummel/patool)
## patool Website
[http://wummel.github.io/patool/](http://wummel.github.io/patool)


