require('hw.arm.luaqemu.core')
ffi = require("ffi")
C = ffi.C

-- http://luajit.org/ext_ffi_api.html

machine_cpu = 'cortex-a15'

memory_regions = {
    region_ram = {
        name = 'mem_ram',
        start = 0xfe800000,
        size = 0x500000
    },
}

file_mappings = {
    main_ram = {
        name = 'kernel',
        type = 'elf'
    }
}

function lua_stuck_cb()
    C.printf("CPU is stuck around 0x%x\n", lua_get_pc())
    local rregs = lua_get_all_registers()
    for idx, val in ipairs(rregs) do
        C.printf("r%d\t0x%x\n", ffi.new('int',idx-1), val);
    end
    -- lua_continue()
end

-- we deal with unknown instruction exception here
-- why: qcomm has some private cp15 registers which cannot be recognized by qemu
function lua_do_interrupt_cb(exception_index)
    print("an exception occurs")
    pc = tonumber(lua_get_pc())
    print("[*] test exception occurs at ", pc);
    print("[*] exception_index ", exception_index);

    if exception_index ~= 1 then
        -- todo: other exceptions
        lua_continue()
    end

    -- -- get the pc/and instruction
    insn = lua_read_dword(pc)
    print ("[*] insn ", insn);


end



cpu = {
    env = {
        thumb = false,
        stuck_max = 300,
        stuck_cb = lua_stuck_cb,
        regs = {}
    },
    callbacks = {
        do_interrupt_cb = lua_do_interrupt_cb,
    },

    -- reset pc to the start of smc handler
    reset_pc = 0xfe810000
}


function mem_access(args)
   local pc = lua_get_pc()
   C.printf("mem access@0x%08llx accessing 0x%08llx (%lld) (%lld)\n", lua_get_pc(), args.addr, args.len, args.flags)

end

-- break points functions
function bp_early_patch()
    lua_watchpoint_insert(tonumber(0xfe810000),400,WP_MEM_READ,mem_access)
    lua_watchpoint_insert(tonumber(0xfe810000),400,WP_MEM_WRITE,mem_access)
    lua_watchpoint_insert(tonumber(0xfe810000),400,WP_MEM_ACCESS,mem_access)
    -- accessed by 0xfe810020
    --lua_write_dword(0xfe838300, 0xfe838300)
    -- patch instructions accessing unknown coop to NOP (we may need more)
    lua_set_register(0,0x1)
    lua_set_register(13,0xfe838200)
    lua_write_dword(0xfe838300,0x0)
    lua_write_dword(0xfe80f7c4, 0x0)
    lua_write_dword(0xfe80f7c8, 0x0)
    lua_write_dword(0xfe80f8ac, 0x0)
    lua_write_dword(0xfe80f83c, 0x0)
    lua_write_dword(0xfe80fd08, 0x0)
    lua_write_dword(0xfe80fe64, 0x0)
    lua_write_dword(0xfe80fe70, 0x0)
    lua_write_dword(0xfe80fe74, 0x0)
    lua_write_dword(0xfe80fe80, 0x0)
    lua_write_dword(0xfe80feb0, 0x0)
    lua_write_dword(0xfe80fec0, 0x0)
    --lua_write_dword(0xfe80fec8, 0x0)
    --lua_write_dword(0xfe80fed0, 0x0)
    --here--lua_write_dword(0xfe80fed8, 0x0)
    --lua_write_dword(0xfe81ddd4, 0x0)
    --lua_write_dword(0xfe81ddd8, 0x0)
    --lua_write_dword(0xfe81dddc, 0x0)
    --lua_write_dword(0xfe81dde0, 0x0)
    --lua_write_dword(0xfe81dde4, 0x0)
    --lua_write_dword(0xfe81dde8, 0x0)
    --lua_write_dword(0xfe81ddf4, 0x0)
    --lua_write_dword(0xfe81ddf8, 0x0)
    --lua_write_dword(0xfe81ddfc, 0x0)
    --lua_write_dword(0xfe81de00, 0x0)
    --lua_write_dword(0xfe81de10, 0x0)
    --lua_write_dword(0xfe81de20, 0x0)
    --lua_write_dword(0xfe80f8ac, 0x0)
    --lua_write_dword(0xfe80f83c, 0x0)
    --lua_write_dword(0xfe80fd08, 0x0)
    --lua_write_dword(0xfe81000c, 0x0)

    -- patch the address to jump to smc handler (donot do this!)
    --lua_write_dword(0xfe81025c, 0xfe81dc00)
    
    -- set register r0 -r3
    -- lua_set_register(0, 0x6001);
    -- lua_set_register(1, 0xdeadfeeb);
    -- lua_set_register(2, 0xFE828444);
    -- lua_set_register(3, 0);

    -- set stack

    lua_continue()
end

-- this is the loop location from __start 
function bp_fe81ddd4()
    -- jump to smc handler
    lua_set_register(15, 0xfe810008);

    -- set register r0 -r3
    lua_set_register(0, 0x4002222);
    lua_set_register(1, 0xaaaaaaaa);
    lua_set_register(2, 0xfe828444);
    --lua_set_register(2, 0xfe827456);
    lua_set_register(3, 0);

    -- write to fe828ac8
    --lua_write_dword(0xfe828ac8, 0xfe82df24)

    lua_continue()
end

function bp_fe80f898()
    -- dump the MVBAR control register
    -- mvbar = lua_get_cp15_register("mvbar");
    -- vbar_s = lua_get_cp15_register("vbar_s");
    -- C.printf("pc 0x%x\n mvbar 0x%x\n", lua_get_register(15), mvbar )
    -- C.printf("pc 0x%x\n vbar_s 0x%x\n", lua_get_register(15), vbar_s )
    lua_continue()
end

function bp_tmp()
    C.printf("reg sp 0x%x\n",lua_get_register(13))
    C.printf("reg 13 +12bits point to 0x%x\n", lua_read_dword(lua_get_register(13))+12)
    C.printf("reg 13 +16bits point to 0x%x\n", lua_read_dword(lua_get_register(13))+16)
    lua_continue()
end

function bp_tmp2()
    C.printf("reg 4: 0x%x\n",lua_get_register(4))
    C.printf("reg 5: 0x%x\n",lua_get_register(5))
    lua_continue()
end

function bp_tmp3()
    C.printf("reg sp 0x%x\n",lua_get_register(13))
    lua_write_dword(lua_get_register(13),0xdeadbeef) 
    --lua_write_dword(0x98, 0xdeadbeef)
    lua_continue()
end

function change_r0()
    --lua_set_register(0, 0xffffffff);
    lua_continue()
end


function dump_memory()
    C.printf("pc 0x%x\n sp 0x%x\n", lua_get_register(15), lua_get_register(13))
    sp = lua_get_register(13)

    i = 0
    while i  <= 32 do
        C.printf("addr 0x%x: 0x%x \n", lua_get_register(13) + i * 4, lua_read_dword(lua_get_register(13) + i * 4))
        i = i + 1
    end

    lua_continue()
end

function change_mmu()
    i = 0
    while i <= 24 do 
        lua_write_dword(0xfe833500+i*4,0xfe840000+i*4096+1630)
        i = i+1
    end
    lua_continue()
    --lua_write_dword(0xfe83ffa0,0xfe800416)
end

breakpoints = {
    -- early patch so that tee os can continue run
    [0xfe810000] = bp_early_patch,
    --[0xfe80f898] = bp_fe80f898,
    --[0xfe80f7f8] = bp_fe80f898,
    --[0xfe80f7c4] = bp_fe`80f7c4,
    --[0xfe81ddd4] = bp_fe81ddd4,
    [0xfe81ac44] = bp_tmp,
    [0xfe81ac68] = bp_tmp2,
    [0xfe81cf9c] = dump_memory,
    [0xfe81cfa4] = dump_memory,
    [0xfe81cfa8] = bp_tmp3,
    [0xfe810028] = change_r0;
    [0xfe81aca8] = change_mmu;
}

function post_init()

end
