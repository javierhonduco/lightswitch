.text

# Frame-pointer prologue/epilogue.
.globl fp_func
.type fp_func,@function
fp_func:
  .cfi_startproc
  pushq %rbp
  .cfi_def_cfa_offset 16
  .cfi_offset %rbp, -16
  movq %rsp, %rbp
  .cfi_def_cfa_register %rbp
  nop
  leave
  .cfi_def_cfa %rsp, 8
  ret
  .cfi_endproc

# Stack-pointer-relative CFA only.
.globl sp_func
.type sp_func,@function
sp_func:
  .cfi_startproc
  subq $32, %rsp
  .cfi_def_cfa_offset 40
  nop
  addq $32, %rsp
  .cfi_def_cfa_offset 8
  ret
  .cfi_endproc

# Unsupported CFA register.
.globl unsupported_reg_func
.type unsupported_reg_func,@function
unsupported_reg_func:
  .cfi_startproc
  .cfi_def_cfa %rax, 8
  nop
  ret
  .cfi_endproc

# CFA offset too large for u16.
.globl cfa_offset_too_large_func
.type cfa_offset_too_large_func,@function
cfa_offset_too_large_func:
  .cfi_startproc
  .cfi_def_cfa %rsp, 70000
  nop
  ret
  .cfi_endproc

# Unsupported DW_CFA_def_cfa_expression pattern.
.globl unsupported_expr_func
.type unsupported_expr_func,@function
unsupported_expr_func:
  .cfi_startproc
  .cfi_escape 0x0f, 0x02, 0x77, 0x08
  nop
  ret
  .cfi_endproc

# Matches PLT1 in src/unwind_info/types.rs.
.globl plt1_func
.type plt1_func,@function
plt1_func:
  .cfi_startproc
  .cfi_escape 0x0f, 0x0b, 0x77, 0x08, 0x80, 0x00, 0x3f, 0x1a, 0x3b, 0x2a, 0x33, 0x24, 0x22
  nop
  ret
  .cfi_endproc

# Matches PLT2 in src/unwind_info/types.rs.
.globl plt2_func
.type plt2_func,@function
plt2_func:
  .cfi_startproc
  .cfi_escape 0x0f, 0x0b, 0x77, 0x08, 0x80, 0x00, 0x3f, 0x1a, 0x3a, 0x2a, 0x33, 0x24, 0x22
  nop
  ret
  .cfi_endproc

# Matches the DerefAndAdd pattern.
.globl deref_add_func
.type deref_add_func,@function
deref_add_func:
  .cfi_startproc
  .cfi_escape 0x0f, 0x05, 0x77, 0x08, 0x06, 0x23, 0x10
  nop
  ret
  .cfi_endproc

# Same as above, with two DW_OP_plus_uconst operations to exercise folding.
.globl deref_add_folded_func
.type deref_add_folded_func,@function
deref_add_folded_func:
  .cfi_startproc
  .cfi_escape 0x0f, 0x07, 0x77, 0x08, 0x06, 0x23, 0x10, 0x23, 0x20
  nop
  ret
  .cfi_endproc

# RBP restored from another register.
.globl rbp_register_func
.type rbp_register_func,@function
rbp_register_func:
  .cfi_startproc
  .cfi_register %rbp, %rbx
  nop
  ret
  .cfi_endproc

# RBP restored from an expression.
.globl rbp_expression_func
.type rbp_expression_func,@function
rbp_expression_func:
  .cfi_startproc
  .cfi_escape 0x10, 0x06, 0x02, 0x77, 0x08
  nop
  ret
  .cfi_endproc

# RBP offset too large for i16.
.globl rbp_offset_too_large_func
.type rbp_offset_too_large_func,@function
rbp_offset_too_large_func:
  .cfi_startproc
  .cfi_offset %rbp, -40000
  nop
  ret
  .cfi_endproc

# Return address is explicitly undefined.
.globl undefined_ra_func
.type undefined_ra_func,@function
undefined_ra_func:
  .cfi_startproc
  .cfi_undefined %rip
  nop
  ret
  .cfi_endproc
