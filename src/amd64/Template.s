.text
.p2align 3
.globl	_Template_begin
.globl  Template_begin
_Template_begin:
Template_begin:

pushq   %r14 # callee saves
pushq   %r13 # callee saves
pushq   %r12 # callee saves
pushq	%rdi # arg 0 (the registers)

# The generated code is kind of picky about which registers it uses
# Easier to just flip the counter over to r14
movq    %rsi, %r14

movq    56(%rdi), %r11
movq    48(%rdi), %r10
movq    40(%rdi), %r9
movq    32(%rdi), %r8
movq    24(%rdi), %rcx
movq    16(%rdi), %r12
movq     8(%rdi), %rsi
movq     0(%rdi), %rdi # clobber arg0

.globl _Template_insertion_point
.globl Template_insertion_point
_Template_insertion_point:
Template_insertion_point:

### Testing
#nop
#nop
#addq $1, %rdi
#addq $2, %rsi
#addq $3, %r12
#addq $4, %rcx
#addq $5, %r8
#addq $6, %r9
#addq $7, %r10
#addq $8, %r11
#nop
#nop

popq %rax # recover arg0 to rax
movq    %r11, 56(%rax)
movq    %r10, 48(%rax)
movq    %r9,  40(%rax)
movq    %r8,  32(%rax)
movq    %rcx, 24(%rax)
movq    %r12, 16(%rax)
movq    %rsi, 8(%rax)
movq    %rdi, 0(%rax)

popq %r12 # callee saves
popq %r13 # callee saves
popq %r14 # callee saves

retq

.globl	_Template_end
.globl  Template_end
_Template_end:
Template_end: