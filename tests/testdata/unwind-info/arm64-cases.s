.text

# Standard x29/x30 frame layout: should map to Arm64ReturnAddressFrame.
.globl frame_ra_func
.type frame_ra_func,%function
frame_ra_func:
  .cfi_startproc
  stp x29, x30, [sp, #-16]!
  .cfi_def_cfa_offset 16
  .cfi_offset x29, -16
  .cfi_offset x30, -8
  mov x29, sp
  .cfi_def_cfa_register x29
  nop
  ldp x29, x30, [sp], #16
  .cfi_def_cfa sp, 0
  ret
  .cfi_endproc

# Return address saved away from the frame-pointer layout.
.globl ra_elsewhere_func
.type ra_elsewhere_func,%function
ra_elsewhere_func:
  .cfi_startproc
  sub sp, sp, #32
  .cfi_def_cfa_offset 32
  str x29, [sp]
  .cfi_offset x29, -32
  str x30, [sp, #24]
  .cfi_offset x30, -8
  nop
  add sp, sp, #32
  .cfi_def_cfa_offset 0
  ret
  .cfi_endproc

# No explicit return-address rule: should map to Arm64ReturnAddressLr.
.globl ra_lr_func
.type ra_lr_func,%function
ra_lr_func:
  .cfi_startproc
  nop
  ret
  .cfi_endproc

# Return-address offset too large for i16.
.globl ra_offset_too_large_func
.type ra_offset_too_large_func,%function
ra_offset_too_large_func:
  .cfi_startproc
  .cfi_offset x29, -40000
  .cfi_offset x30, -39992
  nop
  ret
  .cfi_endproc
