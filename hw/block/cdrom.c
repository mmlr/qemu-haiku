/*
 * QEMU ATAPI CD-ROM Emulator
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* ??? Most of the ATAPI emulation is still in ide.c.  It should be moved
   here.  */

#include "qemu-common.h"
#include "hw/scsi/scsi.h"

static void lba_to_msf(uint8_t *buf, int lba)
{
    lba += 150;
    buf[0] = (lba / 75) / 60;
    buf[1] = (lba / 75) % 60;
    buf[2] = lba % 75;
}

static int cdrom_empty_track_map[1] = { 0 };
static int *cdrom_track_map = cdrom_empty_track_map;
static bool cdrom_track_map_built = false;
static int cdrom_track_count = 1;

int *cdrom_build_toc(void);

int *
cdrom_build_toc(void)
{
    const char *buffer = cdrom_toc;

    if (cdrom_track_map_built) {
        return cdrom_track_map;
    }

    /* there can be a maximum of 100 tracks per CD */
    cdrom_track_map = (int *)malloc(100 * sizeof(int));
    memset(cdrom_track_map, 0, 100 * sizeof(int));
    cdrom_track_count = 0;

    while (true) {
        int sector;
        if (sscanf(buffer, "%d", &sector) != 1)
            break;

        cdrom_track_map[cdrom_track_count++] = sector;
        buffer = strstr(buffer, ",");
        if (!buffer)
            break;

        buffer++;
    }

    if (cdrom_track_count == 0) {
        cdrom_track_count = 1;
        cdrom_track_map[0] = 0;
    }

    if (cdrom_track_map[0] != 0)
        printf("warning: cdrom track 1 not starting at sector 0\n");

    cdrom_track_map_built = true;
    return cdrom_track_map;
}

/* same toc as bochs. Return -1 if error or the toc length */
/* XXX: check this */
int cdrom_read_toc(int nb_sectors, uint8_t *buf, int msf, int start_track)
{
    uint8_t *q;
    int len, i;

    cdrom_build_toc();

    if (start_track > cdrom_track_count && start_track != 0xaa)
        return -1;

    q = buf;
    q += 2; /* toc length written at the end */

    *q++ = 1; /* first track */
    *q++ = cdrom_track_count; /* last track */

    for (i = 0; i < cdrom_track_count; i++) {
        *q++ = 0; /* reserved */
        *q++ = 0x10; /* ADR, control */
        *q++ = i + 1;    /* track number */
        *q++ = 0; /* reserved */
        if (msf) {
            *q++ = 0; /* reserved */
            lba_to_msf(q, cdrom_track_map[i]);
            q += 3;
        } else {
            /* sector 0 */
            stl_be_p((uint32_t *)q, cdrom_track_map[i]);
            q += 4;
        }
    }

    /* lead out track */
    *q++ = 0; /* reserved */
    *q++ = 0x16; /* ADR, control */
    *q++ = 0xaa; /* track number */
    *q++ = 0; /* reserved */
    if (msf) {
        *q++ = 0; /* reserved */
        lba_to_msf(q, nb_sectors);
        q += 3;
    } else {
        stl_be_p(q, nb_sectors);
        q += 4;
    }
    len = q - buf;
    stw_be_p(buf, len - 2);
    return len;
}

/* mostly same info as PearPc */
int cdrom_read_toc_raw(int nb_sectors, uint8_t *buf, int msf, int session_num)
{
    uint8_t *q;
    int i, len;

    q = buf + 2;
    *q++ = 1; /* first session */
    *q++ = 1; /* last session */

    *q++ = 1; /* session number */
    *q++ = 0x14; /* data track */
    *q++ = 0; /* track number */
    *q++ = 0xa0; /* lead-in */
    *q++ = 0; /* min */
    *q++ = 0; /* sec */
    *q++ = 0; /* frame */
    *q++ = 0;
    *q++ = 1; /* first track */
    *q++ = 0x00; /* disk type */
    *q++ = 0x00;

    *q++ = 1; /* session number */
    *q++ = 0x14; /* data track */
    *q++ = 0; /* track number */
    *q++ = 0xa1;
    *q++ = 0; /* min */
    *q++ = 0; /* sec */
    *q++ = 0; /* frame */
    *q++ = 0;
    *q++ = cdrom_track_count; /* last track */
    *q++ = 0x00;
    *q++ = 0x00;

    *q++ = 1; /* session number */
    *q++ = 0x14; /* data track */
    *q++ = 0; /* track number */
    *q++ = 0xa2; /* lead-out */
    *q++ = 0; /* min */
    *q++ = 0; /* sec */
    *q++ = 0; /* frame */

    /* The MMC Specification says: "None of the fields in the response data
       of Format 0010b are affected by the TIME bit in the CDB." */
    *q++ = 0; /* reserved */
    lba_to_msf(q, nb_sectors);
    q += 3;

    for (i = 0; i < cdrom_track_count; i++) {
        *q++ = 1; /* session number */
        *q++ = 0x14; /* ADR, control */
        *q++ = i + 1; /* track number */
        *q++ = i + 1; /* point */
        *q++ = 0; /* min */
        *q++ = 0; /* sec */
        *q++ = 0; /* frame */

        *q++ = 0;
        lba_to_msf(q, cdrom_track_map[i]);
        q += 3;
    }

    len = q - buf;
    stw_be_p(buf, len - 2);
    return len;
}
