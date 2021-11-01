require('luaqemu.hw.arm.luaqemu.core')
ffi = require("ffi")
C = ffi.C

physregion_array = {}

machine_cpu = 'arm11mpcore'

memory_regions = {
	region_ram2 = {
		name = 'mem_ram2',
		start = 0xd0000000,
		size = 1024*1024*5,
	},
    region_ram = {
        name = 'mem_ram',
        start = 0x00000000,
        size = 0x8000000
    },
}

file_mappings = {
    main_ram = {
        name = 'kernel',
        type = 'uimage',
	board_id = 0x480,
	ram_size = 1024*1024*128,
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

function dump_mem_0x8000_0x450000()
	file = io.open("images/3_18_oxnas_kernel_raw","wb")
	buf = lua_read_mem(0x8000,0x450000)
	file:write(buf)
	file:close()
	lua_continue()
end

function change_pointers()
	lua_write_dword(0xc03c6f50,0xd0000884)
	lua_write_dword(0xd0010000,0xd0010004)
	lua_write_dword(0xd0010004,1)
	lua_write_dword(0xc03c6f54,0xd0000bcc)
	lua_write_dword(0xc03c6f24,0)
	lua_write_dword(0xc03c6f28,0)
	lua_write_dword(0xc03c6f2c,0)
	lua_write_dword(0xd0001080,0)
	lua_write_dword(0xd0001084,0)
	lua_write_dword(0xd0001088,0)
	lua_write_dword(0xd000108c,0)
	lua_write_dword(0xd0001090,0)
	lua_write_dword(0xd0001094,0)
	lua_write_dword(0xd0001098,0)
	lua_write_dword(0xd000109c,0)
	lua_write_dword(0xd00010a0,0)
	lua_write_dword(0xd00010a4,0)
	lua_write_dword(0xd00010a8,0)
	lua_write_dword(0xd00010ac,0)
	lua_write_dword(0xd00010b0,0)
	lua_write_dword(0xd00010b4,0)
	lua_write_dword(0xd00010b8,0)
	lua_write_dword(0xd00010bc,0)
	lua_write_dword(0xd00010c0,0)
	lua_write_dword(0xd00010c4,0)
	lua_write_dword(0xd00010c8,0)
	lua_write_dword(0xd00010cc,0)
	lua_write_dword(0xd00010d0,0)
	lua_continue()
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
    -- reset_pc = 0xfe810000
}


function mem_access(args)
   local pc = lua_get_pc()
   C.printf("mem access@0x%08llx accessing 0x%08llx (%lld) (%lld)\n", lua_get_pc(), args.addr, args.len, args.flags)

end

-- break points functions
function bp_early_patch()
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


breakpoints = {
	[0xc03ada08] = change_pointers,
    -- early patch so that tee os can continue run
}


function print_r ( t )  
    local print_r_cache={}
    local function sub_print_r(t,indent)
        if (print_r_cache[tostring(t)]) then
            print(indent.."*"..tostring(t))
        else
            print_r_cache[tostring(t)]=true
            if (type(t)=="table") then
                for pos,val in pairs(t) do
                    if (type(val)=="table") then
                        print(indent.."["..pos.."] => "..tostring(t).." {")
                        sub_print_r(val,indent..string.rep(" ",string.len(pos)+8))
                        print(indent..string.rep(" ",string.len(pos)+6).."}")
                    elseif (type(val)=="string") then
                        print(indent.."["..pos..'] => "'..val..'"')
                    else
                        print(indent.."["..pos.."] => "..tostring(val))
                    end
                end
            else
                print(indent..tostring(t))
            end
        end
    end
    if (type(t)=="table") then
        print(tostring(t).." {")
        sub_print_r(t,"  ")
        print("}")
    else
        sub_print_r(t,"  ")
    end
    print()
end

function read_ops(readcb)
    return physregion_array[tonumber(readcb.addr)]
    --return 0
end

function write_ops(writecb)
    -- Maintain everythng in lua
    physregion_array[tonumber(writecb.addr)] = tonumber(writecb.data)
end 



function add_region(addr, range)
    lua_trapped_physregion_add(addr,range,read_ops,write_ops)
    for i = 0,range do 
        physregion_array[addr+i] = 0
    end
end

function post_init()
	lua_load_file("ventilator/3.x/core_extern_oxnas.o",0xd0000000)
	lua_init_ic_timer_uart(0x44200000,0,13)
end