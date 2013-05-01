/*
 * Regression tests for KQEMU
 * (c) 2005-2007 Fabrice Bellard
 */

.globl _start
        
_start:
        call main
1:      
        jmp 1b
