ENTRY(_start)
SECTIONS
{
  . = 0xf0000000;
  .text      : { *(.text) }
  .rodata    : { *(.rodata) }
  . = ALIGN(4);
  __start_seg_ex_table = . ;
  seg_ex_table : { *(seg_ex_table) }
  __stop_seg_ex_table = . ;
  .data    : { *(.data) }
  .plt      : { *(.plt)	}
  .got           : { *(.got.plt) *(.got) }
  .bss       : {
     *(.bss)
      *(COMMON)
  }   
  . = ALIGN(4096);
  _end = . ;
}
