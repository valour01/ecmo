# CS_ARCH_MIPS, CS_MODE_MIPS32, None
0x10,0x00,0xa4,0xa0 = sb $4, 16($5)
0x10,0x00,0xa4,0xe0 = sc $4, 16($5)
0x10,0x00,0xa4,0xa4 = sh $4, 16($5)
0x10,0x00,0xa4,0xac = sw $4, 16($5)
0x00,0x00,0xa7,0xac = sw $7,  0($5)
0x10,0x00,0xa2,0xe4 = swc1 $f2, 16($5)
0x10,0x00,0xa4,0xa8 = swl $4, 16($5)
0x04,0x00,0xa4,0x80 = lb $4, 4($5)
0x04,0x00,0xa4,0x8c = lw $4, 4($5)
0x04,0x00,0xa4,0x90 = lbu $4, 4($5)
0x04,0x00,0xa4,0x84 = lh $4, 4($5)
0x04,0x00,0xa4,0x94 = lhu $4, 4($5)
0x04,0x00,0xa4,0xc0 = ll $4, 4($5)
0x04,0x00,0xa4,0x8c = lw $4, 4($5)
0x00,0x00,0xe7,0x8c = lw $7, 0($7)
0x10,0x00,0xa2,0x8f = lw $2, 16($sp)
