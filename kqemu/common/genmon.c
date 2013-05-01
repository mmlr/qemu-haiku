/*
 * KQEMU
 *
 * Copyright (C) 2004-2008 Fabrice Bellard
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    int i, c;

    printf("const uint8_t monitor_code[] = {\n");
    i = 0;
    for(;;) {
        c = getchar();
        if (c == EOF)
            break;
        printf("0x%02x,", c);
        i++;
        if (i == 16) {
            printf("\n");
            i = 0;
        }
    }
    printf("\n};\n");
    return 0;
}
