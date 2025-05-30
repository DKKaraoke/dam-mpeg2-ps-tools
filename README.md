# dam-mpeg2-ps-tools

## Summary

DAM Karaoke machines need a GOP index header in MPEG2-PS bitstreams. This software reads and writes DAM Karaoke machine compatible MPEG2-PS.

Also, DAM Karaoke machines need End of sequence (EOS) and End of stream (EOB) NAL units in H.264 bitstreams. Please use it for encoding: https://github.com/DKKaraoke/ffmpeg-x264-add-eos-eob-patched

## Usage

### Dump

```
$ dam-mpeg2-ps-tools dump --help

NAME
    dam-mpeg2-ps-tools dump - Dump

SYNOPSIS
    dam-mpeg2-ps-tools dump INPUT <flags>

DESCRIPTION
    Dump

POSITIONAL ARGUMENTS
    INPUT
        Input MPEG2-PS path

FLAGS
    -p, --print_packets=PRINT_PACKETS
        Default: False
        Print packets. Defaults to False.

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

## Create

```
$ dam-mpeg2-ps-tools create --help

NAME
    dam-mpeg2-ps-tools create - Create

SYNOPSIS
    dam-mpeg2-ps-tools create INPUT OUTPUT <flags>

DESCRIPTION
    Create

POSITIONAL ARGUMENTS
    INPUT
        Input H.264-ES path
    OUTPUT
        Output MPEG2-PS path

FLAGS
    -c, --codec=CODEC
        Default: 'avc'
        Codec. Defaults to "avc".
    -f, --frame_rate=FRAME_RATE
        Default: '30000/1001'
        Frame rate. Defaults to "30000/1001".

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

## List of verified DAM Karaoke machine

- DAM-XG5000[G,R] (LIVE DAM [(GOLD EDITION|RED TUNE)])
- DAM-XG7000[Ⅱ] (LIVE DAM STADIUM [STAGE])
- DAM-XG8000[R] (LIVE DAM Ai[R])

## Authors

- KIRISHIKI Yudai

## License

[MIT](https://opensource.org/licenses/MIT)

Copyright (c) 2023-2025 KIRISHIKI Yudai
