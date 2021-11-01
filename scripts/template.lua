require('luaqemu.hw.arm.luaqemu.core')
ffi = require("ffi")
C = ffi.C

physregion_array = {}

machine_cpu = 'xxx'

memory_regions = {
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
	board_id = -1,
	ram_size = -1,
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
end