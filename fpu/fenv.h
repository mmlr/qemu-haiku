/* Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/*
 * ISO C 9X 7.6: Floating-point environment	<fenv.h>
 */

/* Modified and simplyfied to fit into QEMU for BeOS - 2005 Michael Lotz */

#ifndef _FENV_H
#define _FENV_H	1

/* Define bits representing the exception.  We use the bit positions
   of the appropriate bits in the FPU control word.  */
enum {
	FE_INVALID = 0x01,
	__FE_DENORM = 0x02,
	FE_DIVBYZERO = 0x04,
	FE_OVERFLOW = 0x08,
	FE_UNDERFLOW = 0x10,
	FE_INEXACT = 0x20
};

#define FE_INVALID		FE_INVALID
#define FE_DIVBYZERO	FE_DIVBYZERO
#define FE_OVERFLOW		FE_OVERFLOW
#define FE_UNDERFLOW	FE_UNDERFLOW
#define FE_INEXACT		FE_INEXACT

#define FE_ALL_EXCEPT \
	(FE_INEXACT | FE_DIVBYZERO | FE_UNDERFLOW | FE_OVERFLOW | FE_INVALID)

/* The ix87 FPU supports all of the four defined rounding modes.  We
   use again the bit positions in the FPU control word as the values
   for the appropriate macros.  */
enum {
	FE_TONEAREST = 0,
	FE_DOWNWARD = 0x400,
	FE_UPWARD = 0x800,
	FE_TOWARDZERO = 0xc00
};

#define FE_TONEAREST	FE_TONEAREST
#define FE_DOWNWARD	FE_DOWNWARD
#define FE_UPWARD	FE_UPWARD
#define FE_TOWARDZERO	FE_TOWARDZERO

/* Type representing exception flags.  */
typedef unsigned short int fexcept_t;

/* Type representing floating-point environment.  This function corresponds
   to the layout of the block written by the `fstenv'.  */
typedef struct {
	unsigned short int control_word;
    unsigned short int __unused1;
    unsigned short int status_word;
    unsigned short int __unused2;
    unsigned short int tags;
    unsigned short int __unused3;
    unsigned int eip;
    unsigned short int cs_selector;
    unsigned int opcode:11;
    unsigned int __unused4:5;
    unsigned int data_offset;
    unsigned short int data_selector;
    unsigned short int __unused5;
} fenv_t;

/* If the default argument is used we use this value.  */
#define FE_DFL_ENV		((fenv_t *) -1)
/* Floating-point environment where none of the exception is masked.  */
#define FE_NOMASK_ENV	((fenv_t *) -2)


/* Floating-point exception handling.  */

/* Clear the supported exceptions represented by EXCEPTS.  */
extern void feclearexcept(int excepts);

/* Store implementation-defined representation of the exception flags
   indicated by EXCEPTS in the object pointed to by FLAGP.  */
extern void fegetexceptflag(fexcept_t *flagp, int excepts);

/* Raise the supported exceptions represented by EXCEPTS.  */
extern void feraiseexcept(int __excepts);

/* Set complete status for exceptions indicated by EXCEPTS according to
   the representation in the object pointed to by FLAGP.  */
extern void fesetexceptflag(const fexcept_t *flagp, int excepts);

/* Determine which of subset of the exceptions specified by EXCEPTS are
   currently set.  */
extern int fetestexcept(int excepts);


/* Rounding control.  */

/* Get current rounding direction.  */
extern int fegetround(void);

/* Establish the rounding direction represented by ROUND.  */
extern int fesetround(int __rounding_direction);


/* Floating-point environment.  */

/* Store the current floating-point environment in the object pointed
   to by ENVP.  */
extern void fegetenv(fenv_t *__envp);

/* Save the current environment in the object pointed to by ENVP, clear
   exception flags and install a non-stop mode (if available) for all
   exceptions.  */
extern int feholdexcept(fenv_t *__envp);

/* Establish the floating-point environment represented by the object
   pointed to by ENVP.  */
extern void fesetenv(__const fenv_t *__envp);

/* Save current exceptions in temporary storage, install environment
   represented by object pointed to by ENVP and raise exceptions
   according to saved exceptions.  */
extern void feupdateenv(__const fenv_t *__envp);

#endif /* fenv.h */
