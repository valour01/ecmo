import os
import sys 
import subprocess
import struct
import shutil
import tempfile
import qmp
from configparser import ConfigParser
from match import Disasm
from pyqemulog import get_pql
from threading import Timer
#from elftools.elf.elffile import ELFFile

class ECMO:
    def __init__(self,config_path):
        self.config_path = config_path
        #self.src_config_path = src_config_path
   
    #def load_src_config(self):
        #self.src_config = ConfigParser()
        #self.src_config.read(self.src_config_path)


    def load_config(self):
        self.config = ConfigParser()
        self.config.read(self.config_path)

        self.version = self.config.get("global","version")

        self.machine_cpu = self.config.get("global","machine_cpu")
        self.board_id = self.config.get("global","board_id")
        self.image_path = self.config.get("global","image_path")
        self.decompressed_kernel = self.config.get("global","kernel_path")
        self.src_info_config = self.config.get("global","src_info_config")
        if "dtb_path" in self.config["global"]:
            self.dtb_path = self.config.get("global","dtb_path")
        else:
            self.dtb_path = None
        self.base_addr = self.config.get("global","base_addr")

        self.get_irq_raw_path = None 
        self.get_irq_raw_load_addr = None

        if "get_irq_raw_path" in self.config["global"]:
            self.get_irq_raw_path = self.config.get("global","get_irq_raw_path")
        if "get_irq_raw_load_addr" in self.config["global"]:
            self.get_irq_raw_load_addr = self.config.get("global","get_irq_raw_load_addr")
        self.ram_size = 1024*1024*32 
        if "ram_size" in self.config["global"]:
            self.ram_size = self.config.get("global","ram_size") 

        #self.uart_base = self.config.get("uart","base")
        #self.uart_it_shift = self.config.get("uart","it_shift")
        #self.uart_irq = self.config.get("uart","irq")

        self.components_size = self.config.get("global","components_size")
        self.components_load_addr = self.config.get("global","components_load_addr")
        self.components_patch_internal_path = self.config.get("global","components_patch_internal_path")
        self.components_patch_extern_path = self.config.get("global","components_patch_extern_path")
        self.template_lua_path = self.config.get("global","template_lua_path")
        self.target_lua_path = self.config.get("global","target_lua_path")
        self.start_kernel_addr = self.config.get("global","start_kernel_addr")

        #self.init_irq_pointer = self.config.get("rewrite","init_irq_pointer")
        self.init_irq_pointer = None
        self.init_irq_addr = self.config.get("rewrite","init_irq_addr")
        self.timer_pointer =None
        self.timer_addr = self.config.get("rewrite","timer_addr")
        self.init_machine_pointer = None
        self.init_machine_addr = self.config.get("rewrite","init_machine_addr")

        self.get_irqnr_orig_start = None 
        self.get_irqnr_orig_end = None 
        self.get_irqnr_load_addr = None 
        self.get_irqnr_code_size = None 

        #if "get_irqnr_orig_start" in self.config["rewrite"]:
        #    self.get_irqnr_orig_start = self.config.get("rewrite","get_irqnr_orig_start")
        #if "get_irqnr_orig_end" in self.config["rewrite"]:
        #    self.get_irqnr_orig_end = self.config.get("rewrite","get_irqnr_orig_end")
        if "get_irqnr_load_addr" in self.config["rewrite"]:
            self.get_irqnr_load_addr = self.config.get("rewrite","get_irqnr_load_addr")
        if "get_irqnr_code_size" in self.config["rewrite"]:
            self.get_irqnr_code_size = self.config.get("rewrite","get_irqnr_code_size")

        self.qemu_path = self.config.get("qemu","qemu_path")
        self.run_args = self.config.get("qemu","run_args")
        self.log = self.config.get("qemu","log")

        if "uart_base" in self.config["qemu"]:
            self.uart_base = self.config.get("qemu","uart_base")
        else:
            self.uart_base = None

        self.kernel_length= self.config.get("global","kernel_length")

        self.missed_regions = {}
        if self.log:
            self.log_option = self.config.get("qemu","log_option")
            self.log_file = self.config.get("qemu","log_file")
        
    def rewrite_dtb(self):
        print("rewrite dtb")

    def patch_pointers(self):
        self.patch_unknown_errors()
        self.patch_internal_pointers()
        self.patch_extern_pointers()        

    def get_component_addr_offset(self,addr):
        offset = -1
        self.init_text_start = -1 
        self.init_text_offset = -1 
        self.init_text_size = -1 
        if "init_text_start" in self.config["elf"]:
            self.init_text_start = int(self.config.get("elf","init_text_start"),16)
        if "init_text_offset" in self.config["elf"]:
            self.init_text_offset = int(self.config.get("elf","init_text_offset"),16)
        if "init_text_size" in self.config["elf"]:
            self.init_text_size = int(self.config.get("elf","init_text_size"),16)

        self.text_start = -1 
        self.text_offset = -1 
        self.text_size = -1 
        if "text_start" in self.config["elf"]:
            self.text_start = int(self.config.get("elf","text_start"),16)
        if "text_offset" in self.config["elf"]:
            self.text_offset = int(self.config.get("elf","text_offset"),16)
        if "text_size" in self.config["elf"]:
            self.text_size = int(self.config.get("elf","text_size"),16)

        self.bss_start = -1 
        self.bss_offset = -1 
        self.bss_size = -1 
        if "bss_start" in self.config["elf"]:
            self.bss_start = int(self.config.get("elf","bss_start"),16)
        if "bss_offset" in self.config["elf"]:
            self.bss_offset = int(self.config.get("elf","bss_offset"),16)
        if "bss_size" in self.config["elf"]:
            self.bss_size = int(self.config.get("elf","bss_size"),16)


        self.data_start = int(self.config.get("elf","data_start"),16)
        self.data_offset = int(self.config.get("elf","data_offset"),16)
        self.data_size = int(self.config.get("elf","data_size"),16)

        self.rodata_start = int(self.config.get("elf","rodata_start"),16)
        self.rodata_offset = int(self.config.get("elf","rodata_offset"),16)
        self.rodata_size = int(self.config.get("elf","rodata_size"),16)


        if addr >= self.init_text_start and addr< self.init_text_start + self.init_text_size:
            offset = self.init_text_offset + addr - self.init_text_start 
        if addr >= self.data_start and addr < self.data_start + self.data_size:
            offset = self.data_offset + addr -self.data_start 
        if addr >= self.rodata_start and addr < self.rodata_start + self.rodata_size:
            offset = self.rodata_offset + addr - self.rodata_start 
        if addr >= self.bss_start and addr < self.bss_start + self.bss_size:
            offset = self.bss_offset + addr - self.bss_start 
        if addr >= self.text_start and addr < self.text_start + self.text_size:
            offset = self.text_offset + addr - self.text_start 
        return offset

    def patch_unknown_errors(self):
        print("Patch unknown errors")
        self.components_general_path = self.config.get("global","components_general_path")
        f = open(self.components_general_path,"rb")
        raw = f.read()
        f.close() 
        self.jump_error = eval(self.config.get("elf","jump_error"))
        byte_num = int(len(raw)/4)
        for i in range(byte_num):
            if i in self.jump_error:
                right_raw = struct.pack("I",self.jump_error[i])
                raw = raw[:i*4]+right_raw+raw[(i+1)*4:]
        self.components_patched_error_path = self.config.get("global","components_patched_error_path")
        f = open(self.components_patched_error_path,"wb")
        f.write(raw)
        f.close()




    def patch_internal_pointers(self):
        print("Patch internal pointers")
        self.components_patched_error_path = self.config.get("global","components_patched_error_path")
        f = open(self.components_patched_error_path,"rb")
        raw = f.read()
        f.close()
        addr_items = self.config["internal_addrs"]
        for addr_item in addr_items:
            addrs = eval(self.config.get("internal_addrs",addr_item))
            pointer_value = int(self.config.get("internal_pointers",addr_item.replace("addrs","pointer_value")),16)
            pointer_offset = int(self.components_load_addr,16) + self.get_component_addr_offset(pointer_value)
            for addr in addrs:
                offset = self.get_component_addr_offset(addr)
                print(addr_item,":",hex(offset),":",hex(pointer_offset))
                raw = raw[:offset] + struct.pack("I",pointer_offset) +raw[offset+4:]
        f = open(self.components_patch_internal_path,"wb")
        f.write(raw)
        f.close()
            


    def patch_extern_pointers(self):
        print("Patch extern pointers")
        f = open(self.components_patch_internal_path,"rb")
        raw = f.read()
        f.close() 
        addr_items = self.config["extern_addrs"]
        for addr_item in addr_items:
            addrs = eval(self.config.get("extern_addrs",addr_item))
            if addr_item == "cpu_possible_mask_addrs":
                pointer_value = 0xd0010000
            else:
                pointer_value = self.extern_values[addr_item.replace("_addrs","")]

            for addr in addrs:
                offset = self.get_component_addr_offset(addr)
                #try to force the value of cpu_possible_mask
                print(addr_item,":",hex(offset),":",hex(pointer_value))
                raw = raw[:offset] + struct.pack("I",pointer_value)+raw[offset+4:]
        f = open(self.components_patch_extern_path,"wb")
        f.write(raw)
        f.close()


    def init_lua_script(self):
        print("init lua script")
        f = open(self.template_lua_path,"r")
        lua_scripts = f.readlines()
        f.close()
        rewritten = False
        f2 = open(self.target_lua_path,"w")
        for script in lua_scripts:
            if "machine_cpu = 'xxx'" in script:
                script = script.replace("xxx",self.machine_cpu)
            if "board_id = -1" in script:
                script = script.replace("-1",self.board_id)
            if "ram_size = -1" in script:
                script = script.replace("-1",self.ram_size)

            f2.write(script)

            if "post_init()" in script:
                for miss_region in self.missed_regions:
                    f2.write("\tadd_region("+hex(miss_region)+","+hex(self.missed_regions[miss_region])+")\n")
                #f2.write("\tlua_load_file(\""+self.components_patch_extern_path+"\","+self.components_load_addr+")\n")
                if self.get_irq_raw_path != None and self.get_irq_raw_load_addr != None:
                    f2.write("\tlua_load_file(\""+self.get_irq_raw_path+"\","+self.get_irq_raw_load_addr+")\n")
            if "memory_regions" in script:
                f2.write("\tregion_ram2 = {\n")
                f2.write("\t\tname = 'mem_ram2',\n")
                f2.write("\t\tstart = "+self.components_load_addr+ ",\n")
                f2.write("\t\tsize = "+self.components_size + ",\n")
                f2.write("\t},\n")
            if not rewritten and script.startswith("end"):
                f2.write("\nfunction change_pointers()\n")
                #clean the bss section
                if "bss_size" in self.config["elf"]:
                    bss_size = int(self.config.get("elf","bss_size"),16)
                    bss_offset = int(self.config.get("elf","bss_offset"),16)
                    for i in range(int(bss_size/4)):
                        f2.write("\t"+"lua_write_dword("+hex(int(self.components_load_addr,16)+bss_offset+i*4)+","+"0)\n")
                f2.write("\t"+"lua_continue()\n")

                # redirect the get_irqnr
                ldr_inst = 0xe51ff004
                if self.get_irqnr_orig_start != None:
                    f2.write("\t"+"lua_write_dword("+self.get_irqnr_orig_start+","+hex(ldr_inst)+")\n")
                    f2.write("\t"+"lua_write_dword("+hex(int(self.get_irqnr_orig_start,16)+4)+","+str(self.get_irqnr_load_addr)+")\n")
                # redirect the get_irqnr back
                if self.get_irqnr_load_addr != None:
                    f2.write("\t"+"lua_write_dword("+hex(int(self.get_irqnr_load_addr,16)+int(self.get_irqnr_code_size,16))+","+hex(ldr_inst)+")\n")
                    f2.write("\t"+"lua_write_dword("+hex(int(self.get_irqnr_load_addr,16)+int(self.get_irqnr_code_size,16)+4)+","+hex(int(self.get_irqnr_orig_end,16)+4)+")\n")
                f2.write("end\n")
                rewritten = True
            
        f2.close()

       

    def generate_final_lua_script(self):
        print("Generating Final Lua Script")
        f = open(self.target_lua_path,"r")
        lines = f.readlines()
        f.close()
        rewritten = False
        f2 = open(self.target_lua_path+"_tmp","w")
        for l in lines:
            f2.write(l)
            if  l.startswith("function change_pointers()"):
                # set the function pointer for init irq
                print("init_irq_pointer:",hex(self.init_irq_pointer))
                print("init_irq_addr:",self.init_irq_addr)
                f2.write("\t"+"lua_write_dword("+hex(self.init_irq_pointer)+","+hex(int(self.components_load_addr,16)+self.get_component_addr_offset(int(self.init_irq_addr,16)))+")\n")
                # set the value of cpu_possible_mask
                if self.version.startswith("4.4") or self.version.startswith("3.18"):
                    f2.write("\t"+"lua_write_dword(0xd0010000,0xd0010004)\n")
                    f2.write("\t"+"lua_write_dword(0xd0010004,1)\n")
                if self.version.startswith("4.14"):
                    f2.write("\t"+"lua_write_dword(0xd0010000,1)\n")
                # set the data/function pointer for init timer
                f2.write("\t"+"lua_write_dword("+hex(self.timer_pointer)+","+hex(int(self.components_load_addr,16)+self.get_component_addr_offset(int(self.timer_addr,16)))+")\n")
                f2.write("\t"+"lua_write_dword("+hex(self.l2c_pointer)+",0)\n")
                f2.write("\t"+"lua_write_dword("+hex(self.l2c_pointer+4)+",0)\n")
                f2.write("\t"+"lua_write_dword("+hex(self.l2c_pointer+8)+",0)\n")
                # set the init machine pointer for init machine
                # f2.write("\t"+"lua_write_dword("+hex(self.init_machine_pointer)+","+hex(int(self.components_load_addr,16)+self.get_component_addr_offset(int(self.init_machine_addr,16)))+")\n")
            if l.startswith("function post_init()"):
                f2.write("\tlua_load_file(\""+self.components_patch_extern_path+"\","+self.components_load_addr+")\n")
            if "breakpoints = " in l:
                f2.write("\t["+hex(self.extern_values['setup_machine_fdt'])+"] = change_pointers,"+"\n")
            
        f2.close()
        shutil.move(self.target_lua_path+"_tmp",self.target_lua_path)

    def run(self):
        print("run")
        trace_flags = ""
        run_cmd = self.qemu_path + " -kernel "+self.image_path + " "+self.run_args +" -lua "+self.target_lua_path
        if self.log:
            trace_flags = "-d "+self.log_option+" -D "+self.log_file
        self.run_log = self.log_file.replace("qemu.log","run.log")
        if self.dtb_path != None:
            run_cmd = run_cmd +" -dtb "+self.dtb_path
        socket = tempfile.NamedTemporaryFile()
        qmp_flags = "-qmp unix:{},server,nowait".format(socket.name)
        rootfs_cmd = "-initrd rootfs/armel.cpio.rootfs -append \"console=ttyS0 nowatchdog nokaslr\""
        full_cmd = " ".join([run_cmd,trace_flags,qmp_flags,rootfs_cmd])
        print(full_cmd)
        def stop(p):
            print("Timeout exception")
            qemu = qmp.QEMUMonitorProtocol(socket.name)
            qemu.connect()
            qemu.cmd('quit')
            qemu.close()
            socket.close()

        p = subprocess.Popen(full_cmd, shell = True, universal_newlines = True, stdout = subprocess.PIPE,stderr = subprocess.STDOUT)
        timer = Timer(20,stop,args = [p])
        timer.start()
        f = open(self.run_log,'w')
        for line in p.stdout:
            f.write(line)
        f.close()
        timer.cancel()
        #subprocess.Popen()

    def check_miss_region(self):
        print("Check the miss region")
        f = open(self.log_file,"r")
        lines = f.readlines()
        f.close()
        for l in lines:
            if "DEBUG: Memory Error" in l:
                miss_region = hex(l.split("physaddr:")[1].split("virtaddr")[0].strip(),16)&0xffffff00 
                miss_size = hex(l.split("size:")[1],16)|0xff
                self.missed_regions[miss_region] = miss_size
                
    def generate_config(self):
        # feed the image to match script
        # generate the value of required script
        pass


    def identify_mach_desc(self):
        setup_machine_fdt = self.extern_values['setup_machine_fdt']
        pql = get_pql('aarch32','little',self.log_file)
        pql.load_cpurf()
        pql.load_in_asm()
        bb = None
        for cpurf in pql.cpurfs.values():
            bb = pql.get_bb(cpurf)
            insts = bb['instructions']
            flag = False
            for inst in insts:
                if inst['opcode'] == 'bl':
                    if inst['operand'][0] == '#'+str(setup_machine_fdt):
                        flag = True
            if flag == True:
                break
        call_inst_addr = int(bb['instructions'][-1]['address'],16)
        return_inst = call_inst_addr + 4
        for cpurf in pql.cpurfs.values():
            if int(cpurf['register_files']['R15'],16) == return_inst:
                mach_desc = int(cpurf['register_files']['R00'],16)
                print("mach_desc is 0x%x"%mach_desc)
                self.mach_desc = mach_desc
                self.init_irq_pointer = self.mach_desc + 0x50
                self.timer_pointer = self.mach_desc +  0x54
                self.init_machine_pointer = self.mach_desc + 0x58
                self.l2c_pointer = self.mach_desc + 0x24
                print("mach desc: 0x%x"%mach_desc)
                return mach_desc
        return -1




    def identify_decompress_kernel(self):
        """
        Pattern for 3.18
        mov r0, #0
        str r0, [r2], #4
        str r0, [r2], #4
        str r0, [r2], #4
        str r0, [r2], #4
        cmp r2, r3
        """
        pql = get_pql('aarch32','little',self.log_file)
        pql.load_cpurf()
        pql.load_in_asm() 
        decompress_kernel = None
        decompress_kernel_caller = None
        for cpurf in pql.cpurfs.values():
            bb = pql.get_bb(cpurf)
            insts = bb['instructions']
            if decompress_kernel != None:
                break
            if len(insts) < 6 and decompress_kernel_caller == None:
                continue
            for i in range(len(insts)-5):
                if insts[i]['opcode']+" "+" ".join(insts[i]['operand']) == "mov r0, #0" and \
                    insts[i+1]['opcode']+" "+" ".join(insts[i+1]['operand']) == "str r0, [r2], #4" and \
                    insts[i+2]['opcode']+" "+" ".join(insts[i+2]['operand']) == "str r0, [r2], #4" and \
                    insts[i+3]['opcode']+" "+" ".join(insts[i+3]['operand']) == "str r0, [r2], #4" and \
                    insts[i+4]['opcode']+" "+" ".join(insts[i+4]['operand']) == "str r0, [r2], #4" and \
                    insts[i+5]['opcode']+" "+" ".join(insts[i+5]['operand']) == "cmp r2, r3":
                        print(insts[i])
                        not_relocated = int(insts[i]['address'],16)
                        decompress_kernel_caller = not_relocated + 0x4 *14
                        if self.version.startswith("2"):
                            decompress_kernel_caller = not_relocated +0x4*19
                        print("decomrpess kernel caller is 0x%x".format(decompress_kernel_caller))
            if decompress_kernel_caller != None:
                for inst in insts:
                    if int(inst['address'],16) == decompress_kernel_caller:
                        print(inst)
                        decompress_kernel = int(inst['operand'][0][1:],16) 

        if decompress_kernel == None:
            print("error")
            return
        print("decompress_kernel: 0x%x"%decompress_kernel)

        return_from_decompress_kernel = decompress_kernel_caller + 0x4 
        print("decompress_kernel_caller: 0x%x"%decompress_kernel_caller)
        kernel_start = None
        kernel_length = None
        for cpurf in pql.cpurfs.values():
            #print(int(cpurf['register_files']['R15'],16))
            if int(cpurf['register_files']['R15'],16) == decompress_kernel:
                kernel_start = int(cpurf['register_files']['R00'],16)
            if int(cpurf['register_files']['R15'],16) == return_from_decompress_kernel:
                kernel_length = int(cpurf['register_files']['R00'],16)
        kernel_length = self.kernel_length 
        self.dump_mem(hex(kernel_start),kernel_length,hex(return_from_decompress_kernel),self.decompressed_kernel)
                    


    def dump_mem(self,start,length,dump_point,file_name):
        f = open(self.target_lua_path,'r')
        f2 = open(self.target_lua_path+"_tmp",'w')
        lines = f.readlines()
        writen = False
        for l in lines:
            f2.write(l)
            if l.startswith("end") and writen == False:
                #add the dump mem lua code here 
                f2.write("\nfunction dump_mem_"+str(start)+"_"+str(length)+"()\n")
                f2.write("\tfile = io.open(\""+file_name+"\",\"wb\")\n")
                f2.write("\tbuf = lua_read_mem("+start+","+length+")\n")
                f2.write("\tfile:write(buf)\n")
                f2.write("\tfile:close()\n")
                f2.write("\tlua_continue()\n")
                f2.write("end\n")
                writen = True
            if "breakpoints = " in l:
                print("set the breakpoint")
                f2.write("\t["+dump_point+"] = dump_mem_"+str(start)+"_"+str( length)+",\n")
        f.close()
        f2.close()
        shutil.move(self.target_lua_path+"_tmp",self.target_lua_path)

    #def identify_uart_base(self):
    #    return 0x42000000

    def disable_dump(self):
        f = open(self.target_lua_path,'r')
        f2 = open(self.target_lua_path+"_tmp",'w')
        lines = f.readlines()
        for l in lines:
            if "] = dump_mem_" not in l:
                f2.write(l)

        f.close()
        f2.close()
        shutil.move(self.target_lua_path+"_tmp",self.target_lua_path)

    def identify_uart_base(self):
        #oxnas
        #uart_base = '0x44200000' 
        #bcm
        #uart_base = '0x18000300'
        if self.uart_base == None:
            #we need to identify the uart_base by analyzing the qemu trace 
            self.uart_base = '0xf1012000'


        f = open(self.target_lua_path,'r')
        f2 = open(self.target_lua_path+"_tmp",'w')
        lines = f.readlines()
        for l in lines:
            f2.write(l)
            if l.startswith("function post_init()"):
                f2.write("\tlua_init_ic_timer_uart("+self.uart_base+",0,13)\n")
        f.close()
        f2.close()
        shutil.move(self.target_lua_path+"_tmp",self.target_lua_path)



    def warm_up(self):
        self.run()
        self.identify_uart_base()

    def warm_up_2(self):
        self.run()
        self.identify_decompress_kernel()
        
    def warm_up_3(self):
        self.run()
        # identify the value of mach_desc 
        self.disable_dump()
        self.match()
        self.identify_mach_desc()


    def post_init(self):
        self.patch_pointers()
        self.generate_final_lua_script()

    def match(self):
        #d = Disasm(self.decompressed_kernel,0xc0008000)
        d = Disasm(self.decompressed_kernel,int(self.base_addr,16))
        results =  d.identify_funcs_with_configs(self.src_info_config)  
        self.extern_values = results 
        

    def analyze(self):
        """
        Step 1: load_config: load the general configuration 

        Step 2: init_lua_script: with the general configuration, init the lua script

        Step 3: warm_up: Identify the uart base address;
                3.1: run: Run image with lua script
                        Kernel will print "Uncrompress Kernel" info, which will result in infinite loop without right 
                        configuration of the uart
                3.2: identify_uart_base: Analysis the trace, identify the uart address, update the lua script with added uart info.

        Step 4: warm_up_2: Identify the decompress_kenrel
                4.1: run: Run image with updated lua script. Kernel will decompress the kernel successfully. 
                4.2:identify_decompress_kernel: Analysis the trace, collect the start and length of the kernel image
                    Update the lua script with code for dumping kernel image

        Step 5: warm_up_3: Dump the kernel image, 
                5.1: run: Run image with updated lua script. Kernel is dumped
                5.2: match: Feed the kernel image into the Matcher. We can get the required data/func pointer
                5.3: identify_mach_desc: Analysis the trace and infer the pointer of mach_desc;
        
        Step 6: post_init: Fixed required pointers dynamically and statically
                6.1: patch_pointers: Rewrite the pointer value of the IC/Timer with the inferred pointers of warm_up_3 
                6.2: generate_final_lua_script: Update the lua script with the required mach_desc info.

        Step 7: Run and Success
        """
        self.load_config()
        self.init_lua_script()
        self.warm_up()
        self.warm_up_2()
        self.warm_up_3()
        self.post_init()
        self.run()

if __name__ == "__main__":
    print("Emulate the target firmware")
    if len(sys.argv)<2:
        print("Please specify the configuration")
    config = sys.argv[1]
    ecmo = ECMO(config)
    ecmo.analyze()
