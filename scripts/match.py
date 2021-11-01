from capstone import *
from capstone.arm import *
from configparser import ConfigParser
from configparser import RawConfigParser
from unicorn import *
from unicorn.arm_const import *
import struct
import logging
import queue

logging.basicConfig(level=logging.INFO,filename = "message.log", filemode = "w")




class Function:
    def __init__(self,start):
        self.start = start
        self.blocks = None
        self.callees = [] 
        self.callers = []
        self.callee_details = []
        self.caller_details = []

    

                    
class Block:
    def __init__(self):
        self.insts = []
        self.successors = []
        self.presuccessors = []
        self.children = None
        self.parents = None
        self.calledBy = []
        self.jumpedBy = []
        self.cond_jumps = []
        self.cond_jumped = []
        self.callees = []
        self.children_edge_num = -1
        self.parents_edge_num = -1
        self.children_loop = -1
        self.parents_loop = -1
        #self.mnemonics = []
        self.data_pointers = []

    def appendInst(self,i):
        self.insts.append(i)
    
    def appendSucc(self,bb):
        self.successors.append(bb)
    
    def appendPreSucc(self,bb):
        self.presuccessors.append(bb)

    def contains_inst(self,inst_id):
        num = 0
        for inst in self.insts:
            if inst.id == inst_id:
                num = num+1 
        return num

    def inst_mnemonics(self):
        inst_mnemonics = []
        for inst in self.insts:
            inst_mnemonics.append(inst.mnemonic)
        return inst_mnemonics
   

    def include(self,insts):
        self_insts_str = []
        for inst in self.insts:
            self_insts_str.append(inst.mnemonic+" "+inst.op_str)
        if insts[1:-1] in str(self_insts_str)[1:-1]:
            return True
        return False

    def get_insts_before(self,target_inst_addr):
        results = []
        if target_inst_addr < self.insts[0].address:
            return 0
        if target_inst_addr > self.insts[-1].address:
            return self.insts 
        for inst in self.insts:
            if inst.address < target_inst_addr:
                results.append(inst)
        return results


    def has_callee_at(self,target_callee):
        for inst in self.insts:
            if inst.id != ARM_INS_BL:
                continue
            if inst.operands[0].type == ARM_OP_IMM:
                callee = inst.operands[0].value.imm 
                if callee <0:
                    callee = callee+0x100000000
                if callee == target_callee:
                    return inst.address
        return -1

    def infinite_loop(self):
        for inst in self.insts:
            if inst.mnemonic+" "+inst.op_str == "b #"+hex(inst.address):
                return True
        return False


class Disasm:
    def __init__(self,raw_path,load_address):
        print("init")
        self.raw_path = raw_path
        self.load_address = load_address
        self.md_arm = Cs(CS_ARCH_ARM,CS_MODE_ARM)
        self.md_arm.detail = True
        self.enable_emu = False
        self.curr_queue = []
        self.insts = {}
        self.disasm_set = set()
        self.callee_caller = {}
        self.blocks = {}
        self.funcs = {}
        self.read_bytes()
        self.data = set()
        self.disasm_all()
        self.gen_basic_blocks()
        self.analysis_block()
        self.calc_children_and_parents()
        self.analysis_funcs()
        self.warn_null = None
        self.func_info = {}
        self.identified_addrs = []


    def identify_irq_handler_start(self):
        candidates = []
        for block_addr in self.blocks:
            block = self.blocks[block_addr]
            if len(block.insts)<12:
                continue 
            if len(block.callees) >0:
                continue
            for i in range(len(block.insts)-12):
                if block.insts[i].mnemonic+" "+block.insts[i].op_str == "sub sp, sp, #0x44" and \
                        block.insts[i+1].mnemonic+" "+block.insts[i+1].op_str == "tst sp, #4" and \
                        block.insts[i+2].mnemonic+" "+block.insts[i+2].op_str == "subeq sp, sp, #4" and \
                        block.insts[i+3].mnemonic+" "+block.insts[i+3].op_str == "stm sp, {r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip}" and \
                        block.insts[i+4].mnemonic+" "+block.insts[i+4].op_str == "ldm r0, {r1, r2, r3}":
                    candidates.append(block.insts[i].address)
        return candidates[0]+0x30


    def identify_irq_handler_end(self,handler_start_address):
        for i in range(100):
            try:
                print(i)
                if self.insts[handler_start_address+4*(i+1)].mnemonic + " "+self.insts[handler_start_address+4*(i+1)].op_str == "movne r1, sp" and \
                        "subne lr" in (self.insts[handler_start_address+4*(i+2)].mnemonic + " "+self.insts[handler_start_address+4*(i+2)].op_str):
                    return handler_start_address+4*(i+1)
            except Exception as e:
                print(str(e))
                return -1
        return -1



    def inside_binary(self,addr):
        if addr >= self.load_address and addr < self.load_address + self.length:
            return True 
        return False

    def identify_warn_null(self,warn_slowpath_null_paras):
        for para in warn_slowpath_null_paras:
            filename = para[0]
            linenum = para[1]
            print(filename)
            print(linenum)
            for func in self.funcs:
                function = self.funcs[func]
                if function.blocks == None:
                    continue 
                for block_addr in function.blocks:
                    if block_addr not in self.blocks:
                        continue 
                    block = self.blocks[block_addr]
                    visited_insts = []
                    for inst in block.insts:
                        visited_insts.append(inst)
                        if inst.id == ARM_INS_BL:
                            flag = False
                            if self.has_string(block_addr,filename):
                                #Check R1: line number
                                for visit_inst in reversed(visited_insts):
                                    if self.set_reg_imm(visit_inst,ARM_REG_R1,linenum):
                                        flag = True
                                if self.enable_emu:
                                    emulate_line = self.get_reg_emulated(visited_insts,UC_ARM_REG_R1) 
                                    if emulate_line == linenum:
                                        flag = True
                            if flag == True:
                                print("inst addr:0x%x"%inst.address)
                                self.warn_null = self.get_callee(inst) 
                                return True 
        return False
 

    def get_start_address_for_emulation(self,insts):
        for inst in insts:
            if inst.id in  (ARM_INS_LDM,): 
                for operand in inst.operands:
                    if operand.type == ARM_OP_REG:
                        if operand.value.reg == ARM_REG_PC:
                            return inst.address
        return insts[0].address


    def has_string(self,block_addr,target_string):
        string_len = len(target_string)
        if block_addr not in self.blocks:
            return 
        block = self.blocks[block_addr]
        reg_value = {}
        for inst in block.insts:
            if inst.id == ARM_INS_LDR:
                if len(inst.operands) == 2:
                    op2 = inst.operands[1]
                    if op2.type == ARM_OP_MEM:
                        if op2.value.mem.base == ARM_REG_PC:
                            pc_relative = inst.address+ 2*4 + op2.value.mem.disp
                            pointer = self.get_value_at_addr(pc_relative)
                            pointer_string = self.get_string_at_addr(pointer,string_len)
                            if pointer_string == target_string:
                                return True 
            if inst.id == ARM_INS_MOVW:
                if len(inst.operands) == 2:
                    if inst.operands[0].type == ARM_OP_REG and inst.operands[1].type == ARM_OP_IMM:
                        reg = inst.operands[0].reg
                        imm = inst.operands[1].imm
                        if reg in reg_value:
                            orig = reg_value[reg]
                            imm = (orig&0xffff0000)|imm
                        reg_value[reg] = imm 
                        pointer_string = self.get_string_at_addr(imm,string_len)
                        if pointer_string == target_string:
                            return True 
            if inst.id == ARM_INS_MOVT:
                if len(inst.operands) == 2:
                    if inst.operands[0].type == ARM_OP_REG and inst.operands[1].type == ARM_OP_IMM:
                        reg = inst.operands[0].reg
                        imm = inst.operands[1].imm 
                        if reg in reg_value:
                            orig = reg_value[reg]
                            imm = (imm<<16)|(orig&0xffff)
                        reg_value[reg] = imm
                        pointer_string = self.get_string_at_addr(imm,string_len)
                        if pointer_string == target_string:
                            return True
        return False

    def get_reg_emulated(self,insts,reg):
        end_address = insts[-1].address
        start_address = self.get_start_address_for_emulation(insts)
        if end_address - start_address <4:
            return -1
        bytecode = self.get_bytecode_from_to(start_address,end_address) 

        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        print("load address is ",hex(self.load_address))
        mu.mem_map(self.load_address,0x1000*0x1000*0xa)
        print("start_address is ",hex(start_address))
        mu.reg_write(UC_ARM_REG_R0,0xc9000000)
        mu.reg_write(UC_ARM_REG_R1,0xc9000000)
        mu.reg_write(UC_ARM_REG_R2,0xc9000000)
        mu.reg_write(UC_ARM_REG_R3,0xc9000000)
        mu.reg_write(UC_ARM_REG_R4,0xc9000000)
        mu.reg_write(UC_ARM_REG_R5,0xc9000000)
        mu.reg_write(UC_ARM_REG_R6,0xc9000000)
        mu.reg_write(UC_ARM_REG_R7,0xc9000000)
        mu.reg_write(UC_ARM_REG_R8,0xc9000000)
        mu.reg_write(UC_ARM_REG_R9,0xc9000000)
        mu.reg_write(UC_ARM_REG_R10,0xc9000000)
        mu.reg_write(UC_ARM_REG_R11,0xc9000000)
        mu.reg_write(UC_ARM_REG_R12,0xc9000000)
        mu.reg_write(UC_ARM_REG_R13,0xc9000000)
        mu.reg_write(UC_ARM_REG_R14,0xc9000000)
        mu.mem_write(start_address,bytecode)
        mu.emu_start(start_address,start_address+len(bytecode)) 
        return  mu.reg_read(reg)


    def set_reg_imm(self,inst,reg,imm):
        if inst.id in [ARM_INS_MOV,ARM_INS_MOVW]:
            if inst.operands[0].type == ARM_OP_REG:
                if inst.operands[0].reg == reg:
                    if inst.operands[1].type == ARM_OP_IMM:
                        if inst.operands[1].value.imm == imm:
                            return True 
        if inst.id == ARM_INS_LDR:
            if inst.operands[0].type == ARM_OP_REG:
                if inst.operands[0].reg == reg:
                    if inst.operands[1].type == ARM_OP_MEM:
                            if inst.operands[1].value.mem.base == ARM_REG_PC:
                                pc_relative = inst.address+ 2*4 + inst.operands[1].value.mem.disp
                                ldr_value = self.get_value_at_addr(pc_relative)
                                if ldr_value == imm:
                                    return True
        return False

    def has_warn_on(self,block_addr,filename,line):
        block = self.blocks[block_addr]
        visited_insts = []
        emulated_insts = []
        for inst in block.insts:
            visited_insts.append(inst)
            if inst.id == ARM_INS_BL:
                callee = self.get_callee(inst)
                if callee == self.warn_null:
                    # Calling the warn null ; Check parameter;
                    if self.has_string(block_addr,filename):
                        #Check R1: line number
                        for inst in reversed(visited_insts):
                            if self.set_reg_imm(inst,ARM_REG_R1,line):
                                return True 
                        if self.enable_emu:
                            emulate_line = self.get_reg_emulated(visited_insts,UC_ARM_REG_R1) 
                            if emulate_line == line:
                                return True
        return False

    def has_warn_on_in(self,block_addr,filename,line,scope):
        block = self.blocks[block_addr]
        visited_insts = []
        emulated_insts = []
        for inst in block.insts:
            visited_insts.append(inst)
            if inst.id == ARM_INS_BL:
                callee = self.get_callee(inst)
                if callee == self.warn_null:
                    # Calling the warn null ; Check parameter;
                    if self.has_string(block_addr,filename):
                        #Check R1: line number
                        for inst in reversed(visited_insts):
                            for i in range(scope):
                                if self.set_reg_imm(inst,ARM_REG_R1,line+i+1):
                                    return True 
                                if self.set_reg_imm(inst,ARM_REG_R1,line-i-1):
                                    return True
                        if self.enable_emu:
                            emulate_line = self.get_reg_emulated(visited_insts,UC_ARM_REG_R1) 
                            if abs(emulate_line - line) < scope:
                                return True
        return False

   


    def change_reg(self,reg,insts):
        for inst in insts:
            if inst.id in [ARM_INS_MOV, ARM_INS_ADD, ARM_INS_LDR]:
                op0 = inst.operands[0]
                if op0.type == ARM_OP_REG:
                    if op0.reg == reg:
                        return True 
        return False


    def analysis_funcs(self):
        print("Analyzing funcs")
        for func in self.funcs:
            if func not in self.blocks:
                self.funcs[func].blocks = []
                continue
            block = self.blocks[func]
            
            
            block_children = block.children 

            self.funcs[func].blocks = block_children
            callees = []
            for block_addr in self.funcs[func].blocks:
                if block_addr not in self.blocks:
                    continue
                block = self.blocks[block_addr]
                for callee in  block.callees:
                    if callee in self.funcs:
                        callees.append(callee)
                        #if callee not in callees:
                        #    callees.append(callee)
                #for successor in block.successors:
                #    if successor in self.funcs:
                #        if successor not in callees:
                #            callees.append(successor)
            self.funcs[func].callees = list(set(callees))
            self.funcs[func].callee_details = callees
        self.caller_analysis()
        


    def is_root_block(self,block_addr):
        if block_addr not in self.blocks:
            return None
        if block_addr in self.funcs:
            return True
        block = self.blocks[block_addr]
        if len(block.presuccessors) == 0:
            return True 
        else:
            return False

    def is_leaf_block(self,block_addr):
        if block_addr not in self.blocks:
            return None
        block = self.blocks[block_addr]
        if len(block.successors) == 0:
            return True 
        else:
            return False

    def block_children(self,block_addr):
        blocks = []
        appended = []
        q = queue.Queue() 
        q.put(block_addr)
        while not q.empty():
            b_addr = q.get() 
            if b_addr not in self.blocks:
                continue 
            if b_addr not in blocks:
                blocks.append(b_addr)
            block = self.blocks[b_addr]
            succs = block.successors
            for succ in succs:
                if succ not in blocks:
                    if succ in appended:
                        continue
                    appended.append(succ)
                    q.put(succ)
        self.blocks[block_addr].children = blocks


    def block_children_old(self,block_addr,dependency = None):
        if dependency == None:
            curr_dependency = set() 
        else:
            curr_dependency = dependency
        #print ("get children at 0x",hex(block_addr))
        if block_addr not in self.blocks:
            children = set() 
            children.add(-1)
            return children
        block = self.blocks[block_addr]
        if block.children != None:
            return block.children
        children = set()
        loop = 0
        children.add(block_addr)
        curr_dependency.add(block_addr)
        if len(block.successors) == 0:
            self.blocks[block_addr].children = children 
            return children
        else:
            for succ in block.successors:
                if succ in self.funcs:
                    continue
                if succ == block_addr:
                    loop +=1
                    continue
                if succ in curr_dependency:
                    loop +=1
                    continue
                children = children | self.block_children_old(succ,curr_dependency)
            self.blocks[block_addr].children = children
            self.blocks[block_addr].children_loop = loop
            return children
    
    def block_parents(self,block_addr,dependency = None):
        if dependency == None:
            curr_dependency = set()
        else:
            curr_dependency = dependency
        if block_addr not in self.blocks:
            children = set()
            children.add(-1)
            return children
        block = self.blocks[block_addr]
        #if block.parents != None:
        #    return block.parents
        parents = set()
        loop = 0
        parents.add(block_addr)
        curr_dependency.add(block_addr)
        if len(block.presuccessors) == 0:
            self.blocks[block_addr].parents = parents
            return parents
        else :
            for presucc in block.presuccessors:
                if presucc == block_addr:
                    loop +=1
                    continue
                if presucc in curr_dependency:
                    loop +=1
                    continue
                parents = parents | self.block_parents(presucc,dependency=curr_dependency)
            self.blocks[block_addr].parents = parents
            self.blocks[block_addr].parents_loop = loop
            return parents


    def read_bytes(self):
        f = open(self.raw_path,"rb")
        self.raw_bytes = f.read()
        self.length = len(self.raw_bytes)
        #self.raw_bytes = self.raw_bytes
        f.close()

    def get_bytecode(self,address):
        bytecode = self.raw_bytes[address-self.load_address:]
        return bytecode 

    def get_bytecode_from_to(self,from_address,to_address):
        bytecode = self.raw_bytes[from_address - self.load_address:to_address - self.load_address]
        return bytecode 

    def get_value_at_addr(self,address):
        if address < self.load_address or address +4 > self.load_address+self.length:
            return -1
        bytecode = self.get_bytecode_from_to(address,address+4)
        value =  struct.unpack("I",bytecode)[0]
        return value

    def get_string_at_addr(self,address,length):
        bytecode = self.get_bytecode_from_to(address,address+length)
        try:
            strings = bytecode.decode("utf-8")
        except:
            return "ERROR"
        return strings

    def get_callee(self,inst):
        if inst.id != ARM_INS_BL:
            return False 
        if inst.operands[0].type == ARM_OP_IMM:
            callee = inst.operands[0].value.imm 
            if callee <0:
                callee = callee+0x100000000
                return callee 
        return None

    def gen_basic_blocks(self):
        print ("Generating basic blocks")
        bb = Block()
        split_addrs = []
        for i in range(int(len(self.raw_bytes)/4)): 
            if (i *40)%(len(self.raw_bytes)) == 0:
                print ("Completed ",float(i*4)/len(self.raw_bytes))
            if (self.load_address+i*4) not in self.insts.keys():
                if len(bb.insts) >0:
                    self.blocks[bb.insts[0].address] = bb
                    bb = Block()                    
                continue
            inst = self.insts[self.load_address+i*4]
            bb.appendInst(inst)
            if inst.group(ARM_GRP_JUMP): 
                if inst.id in [ARM_INS_BL, ARM_INS_BLX]:
                    callee = self.get_callee(inst)
                    if callee != None :
                        #bb.callees.append(callee)
                        function = Function(callee)
                        self.funcs[callee] = function
                        #logging.info("Type 3: Generating Function 0x%x from instruction"%(callee,inst.address))
                    continue
                if inst.operands[0].type == ARM_OP_IMM:
                    successor = inst.operands[0].value.imm
                    if successor < 0: 
                        successor = successor +0x100000000
                    bb.appendSucc(successor)
                    split_addrs.append(successor)
                    if inst.cc != ARM_CC_AL:
                        bb.cond_jumps.append(successor)
                if inst.cc != ARM_CC_AL:
                    successor = inst.address + inst.size 
                    logging.info("Basic Block 0x%x has successor 0x%x"%(bb.insts[0].address,successor))
                    bb.appendSucc(successor)
                    bb.cond_jumps.append(successor)
                self.blocks[bb.insts[0].address] = bb
                logging.info("Generating Basic Block 0x%x"%bb.insts[0].address)
                for callee in bb.callees:
                    logging.info("Basic Block 0x%x has callee 0x%x"%(bb.insts[0].address,callee))
                bb = Block()
                continue
            elif inst.id in (ARM_INS_LDR,):
                if inst.operands[0].type == ARM_OP_REG:
                    if inst.operands[0].value.reg == ARM_REG_PC:
                        self.blocks[bb.insts[0].address] = bb
                        logging.info("Generating Basic Block 0x%x"%bb.insts[0].address)
                        for callee in bb.callees:
                            logging.info("Basic Block 0x%x has callee 0x%x"%(bb.insts[0].address,callee))
                        bb = Block()
                        continue
            elif inst.id in (ARM_INS_LDM,):
                # There is some exceptions. I fix this for kirkwood
                if inst.cc != ARM_CC_AL:
                    continue
                for operand in inst.operands:
                    if operand.type == ARM_OP_REG:
                        if operand.value.reg == ARM_REG_PC:
                            if len(bb.insts)>0:
                                self.blocks[bb.insts[0].address] = bb
                                logging.info("Generating Basic Block 0x%x"%bb.insts[0].address)
                                for callee in bb.callees:
                                    logging.info("Basic Block 0x%x has callee 0x%x"%(bb.insts[0].address,callee))
                                bb = Block()
                                continue

            elif inst.id in (ARM_INS_POP,):
                if inst.cc != ARM_CC_AL:
                    continue
                if 'pc' in inst.op_str:
                    self.blocks[bb.insts[0].address] = bb
                    logging.info("Generating Basic Block 0x%x"%bb.insts[0].address)
                    for callee in bb.callees:
                        logging.info("Basic Block 0x%x has callee 0x%x"%(bb.insts[0].address,callee))
                    bb = Block()
                    continue
            
            elif inst.id in (ARM_INS_MOV,):
                if inst.cc!=ARM_CC_AL:
                    continue
                if inst.operands[0].type == ARM_OP_REG:
                    if inst.operands[0].value.reg == ARM_REG_PC:
                        self.blocks[bb.insts[0].address] = bb
                        logging.info("Generating Basic Block 0x%x"%bb.insts[0].address)
                        for callee in bb.callees:
                            logging.info("Basic Block 0x%x has callee 0x%x"%(bb.insts[0].address,callee))
                        bb = Block()
                        if  inst.operands[1].type == ARM_OP_IMM:
                            bb.appendSucc(inst.operands[1].value.imm)
                        continue

        for split_addr in split_addrs:
            if split_addr <self.load_address or split_addr > self.load_address+ len(self.raw_bytes):
                continue
            self.split_block_at_addr(split_addr)

        for bb_key in self.blocks.keys():
            bb = self.blocks[bb_key]
            successors = bb.successors
            for succ in successors:
                if succ in self.blocks.keys() :
                    logging.info("Basic Block 0x%x has successor 0x%x"%(bb_key,succ))
                    succ_bb = self.blocks[succ]
                    succ_bb.appendPreSucc(bb_key)


    def analysis_block(self):
        print("Analyzing Basic block")
        for block_addr in self.blocks:
            block = self.blocks[block_addr]
            if len(block.insts) == 0:
                continue 
            for cond_jump in block.cond_jumps:
                if cond_jump not in self.blocks:
                    continue 
                self.blocks[cond_jump].cond_jumped.append(block_addr)
        for block_addr in self.blocks:
            logging.info("Analyzing Basic Block 0x%x"%block_addr)
            block = self.blocks[block_addr]
            if len(block.insts) == 0:
                continue
            if block.insts[0].address in self.funcs:
                continue
            if (block_addr-4) in self.data:
                #It should be the start of a basic block
                function = Function(block_addr)
                self.funcs[block_addr] = function
                logging.info("Type 1: Generating Function 0x%x"%block_addr)
                continue
            if len(block.cond_jumped) >0:
                continue

            flag = False
            for inst in block.insts:
                if inst.id == ARM_INS_PUSH:
                    for operand in inst.operands:
                        if operand.type == ARM_OP_REG:
                            if operand.reg == ARM_REG_LR:
                                flag = True 
                if inst.id == ARM_INS_STR:
                    if len(inst.operands) == 2:
                        if inst.operands[0].type == ARM_OP_REG and inst.operands[1].type == ARM_OP_MEM:
                            if inst.operands[0].reg == ARM_REG_LR and inst.operands[1].reg == ARM_REG_SP:
                                if block_addr not in self.funcs:
                                    flag = True
            if flag == True:
                func_start = block.insts[0].address
                function = Function(func_start)
                self.funcs[func_start] = function
                logging.info("Type 2: Generating Function 0x%x"%func_start)

        for block_addr in self.blocks:
            logging.info("Analyzing Basic Block 0x%x again"%block_addr)
            block = self.blocks[block_addr]
            reg_value = {}
            for inst in block.insts:
                if inst.id == ARM_INS_BL:
                    callee =  self.get_callee(inst)
                    if callee != None:
                        #if callee not in block.callees:
                        self.blocks[block_addr].callees.append(callee)

                if inst.id == ARM_INS_LDR:
                    if len(inst.operands) == 2:
                        op2 = inst.operands[1]
                        if op2.type == ARM_OP_MEM:
                            if op2.value.mem.base == ARM_REG_PC:
                                pc_relative = inst.address+ 2*4 + op2.value.mem.disp
                                data = self.get_value_at_addr(pc_relative)
                                self.blocks[block_addr].data_pointers.append(data)
                if inst.id == ARM_INS_MOV:
                    if len(inst.operands) == 2:
                        if inst.operands[0].type == ARM_OP_REG and inst.operands[1].type == ARM_OP_IMM:
                            imm = inst.operands[1].imm 
                            if self.inside_binary(imm):
                                self.blocks[block_addr].data_pointers.append(imm)
                if inst.id == ARM_INS_MOVW:
                    if len(inst.operands) == 2:
                        if inst.operands[0].type == ARM_OP_REG and inst.operands[1].type == ARM_OP_IMM:
                            reg = inst.operands[0].reg
                            imm = inst.operands[1].imm
                            if reg in reg_value:
                                orig = reg_value[reg]
                                imm = (orig&0xffff0000)|imm
                            reg_value[reg] = imm 
                            if self.inside_binary(imm):
                                self.blocks[block_addr].data_pointers.append(imm)
                if inst.id == ARM_INS_MOVT:
                    if len(inst.operands) == 2:
                        if inst.operands[0].type == ARM_OP_REG and inst.operands[1].type == ARM_OP_IMM:
                            reg = inst.operands[0].reg
                            imm = inst.operands[1].imm 
                            if reg in reg_value:
                                orig = reg_value[reg]
                                imm = (imm<<16)|(orig&0xffff)
                            reg_value[reg] = imm
                            if self.inside_binary(imm):
                                self.blocks[block_addr].data_pointers.append(imm)
            deleted_succs = []
            for successor in block.successors:
                if successor in self.funcs:
                    #if successor not in block.callees:
                    self.blocks[block_addr].callees.append(successor)
                    deleted_succs.append(successor)
            for deleted_succ in deleted_succs:
                self.blocks[block_addr].successors.remove(deleted_succ)




    def split_block_at_addr(self,addr):
        logging.info("Split Basic Block at 0x%x"%addr)
        target_bb_key = self.inst_to_bb_address(addr)
        bb1 = Block()
        bb2 = Block()
        for inst in self.blocks[target_bb_key].insts:
            if inst.address < addr:
                bb1.appendInst(inst)
            if inst.address >= addr:
                bb2.appendInst(inst)
        bb2.successors = self.blocks[target_bb_key].successors
        bb2.cond_jumps = self.blocks[target_bb_key].cond_jumps
        bb1.successors.append(addr)

        #return target_bb, bb1, bb2
        self.blocks[target_bb_key] = bb1
        self.blocks[addr] = bb2

    def inst_to_bb_address(self,inst_addr):
        while inst_addr not in self.blocks.keys():
            inst_addr = inst_addr - 4 
        return inst_addr


    def caller_analysis(self):
        for func in self.funcs:
            function = self.funcs[func]
            if function.callees == None:
                continue
            for callee in function.callees:
                #print(callee)
                if callee not in self.funcs:
                    continue
                #if func not in self.funcs[callee].callers:
                self.funcs[callee].caller_details.append(func)
        for func in self.funcs:
            self.funcs[func].callers = list(set(self.funcs[func].caller_details))


    def disasm_all(self):
        """
        Disassemble the bytecode with specified mode and address
        """
        print("Disassembly the bytecode")
        md = self.md_arm
        #data = set()
        for i in range(int(len(self.raw_bytes)/4)):
            if (i *40)%(len(self.raw_bytes)) == 0:
                print ("Completed ",float(i*4)/len(self.raw_bytes))
            bytecode = self.get_bytecode_from_to(self.load_address+i*4,self.load_address+(i+1)*4)
            for i in md.disasm(bytecode,self.load_address+i*4):
                if "ldr" in i.mnemonic or "str" in i.mnemonic:
                    if len(i.operands) == 2:
                        op2 = i.operands[1]
                        if op2.type == ARM_OP_MEM:
                            if op2.value.mem.base == ARM_REG_PC:
                                pc_relative = i.address+ 2*4 + op2.value.mem.disp
                                self.data.add(pc_relative)
                
                self.insts[i.address] = i
 
        for d in self.data:
            if d in self.insts.keys():
                self.insts.pop(d)




    def calc_children_and_parents(self):
        print(len(self.blocks))
        for block in self.blocks:
            if self.is_root_block(block):
                self.block_children(block)
            if self.is_leaf_block(block):
                self.block_parents(block,None)

        for block in self.blocks:
            children_edge_num = 0
            if self.blocks[block].children != None:
                for child in self.blocks[block].children:
                    if child not in self.blocks:
                        continue
                    children_edge_num += len(self.blocks[child].successors)
                self.blocks[block].children_edge_num = children_edge_num
            parents_edge_num = 0
            if self.blocks[block].parents != None:
                for parent in self.blocks[block].parents:
                    if parent not in self.blocks:
                        continue
                    parents_edge_num += len(self.blocks[parent].presuccessors)
                self.blocks[block].parents_edge_num = parents_edge_num 

    def identify_func_via_strings(self,target_string):
        results = []
        for func in self.funcs:
            function = self.funcs[func] 
            if function.blocks == None:
                continue
            for block_addr in function.blocks:
                if block_addr not in self.blocks:
                    continue
                block = self.blocks[block_addr]
                if len(block.insts) == 0:
                    continue
                if self.has_string(block.insts[0].address,target_string):
                    logging.info("Function 0x%x Block 0x%x has string %s"%(func,block.insts[0].address,target_string))
                    results.append(func)
        return results

    def identify_func_via_warn_on(self,filename,line_num):
        results = []
        for func in self.funcs:
            function = self.funcs[func]
            if function.blocks == None:
                continue 
            for block_addr in function.blocks:
                if block_addr not in self.blocks:
                    continue 
                block = self.blocks[block_addr]
                if len(block.insts) == 0:
                    continue 
                if self.has_warn_on(block.insts[0].address,filename,line_num):
                    results = [func,]
                    return results
                if self.has_warn_on_in(block.insts[0].address,filename,line_num,20):
                    results.append(func)
        return results
   
    def is_identified(self,func_name):
        if func_name in self.func_info:
            if len(self.func_info[func_name]) == 1:
                return True 
        return False

    def has_str_offset(self,func_addr,value):
        function = self.funcs[func_addr]
        if function.blocks == None:
            return False 
        for block_addr in function.blocks:
            if block_addr not in self.blocks:
                continue
            block = self.blocks[block_addr]
            for inst in block.insts:
                if inst.id == ARM_INS_STR:
                    if inst.operands[1].value.mem.disp == value:
                        return True
        return False

    def has_specific_value(self,func_addr,value):
        if value <0:
            mov_value = value + 0x100000000
            mvn_value = -value -1
        else:
            mov_value = value 
            mvn_value = value
        function = self.funcs[func_addr]
        if function.blocks == None:
            return False
        for block_addr in function.blocks:
            if block_addr not in self.blocks:
                continue 
            block = self.blocks[block_addr]
            for inst in block.insts:
                if inst.id == ARM_INS_MOV:
                    for op in inst.operands:
                        if op.type == ARM_OP_IMM:
                            if op.value.imm == mov_value:
                                return True 
                if inst.id == ARM_INS_MVN:
                    for op in inst.operands:
                        if op.type == ARM_OP_IMM:
                            if op.value.imm == mvn_value:
                                return True 
        return False

    def logic_operation_value(self,func_addr,op_id,value):
        function = self.funcs[func_addr]
        if function.blocks == None:
            return False
        for block_addr in function.blocks:
            if block_addr not in self.blocks:
                continue 
            block = self.blocks[block_addr]
            for inst in block.insts:
                if inst.id == op_id:
                    for op in inst.operands:
                        if op.type == ARM_OP_IMM:
                            if op.value.imm == value:
                                return True 
        return False



    def is_illegal_ins(self,i):
        if i.id == ARM_INS_SVC:
            if i.operands[0].type == ARM_OP_IMM:
                if i.operands[0].imm > 0x10000:
                    return True 
        return False

    def is_illegal(self,func_addr):
        if func_addr not in self.funcs:
            return False
        func = self.funcs[func_addr]
        for block_addr in func.blocks:
            block = self.blocks[block_addr]
            for i in block.insts:
                if self.is_illegal_ins(i):
                    return True 
        return False


    def is_recursive(self,func_addr):
        if func_addr not in self.funcs:
            return False
        function = self.funcs[func_addr]
        for block_addr in function.blocks:
            if block_addr not in self.blocks:
                continue 
            block = self.blocks[block_addr]
            for inst in block.insts:
                if inst.id == ARM_INS_BL:
                    callee = self.get_callee(inst)
                    if callee == func_addr:
                        return True 
        return False


    def filter_by_strings(self,config_section):
        strings = eval(config_section["strings"])
        results = list(self.funcs) 
        while True:
            target_string = strings.pop()
            old_results = results
            results = self.identify_func_via_strings(target_string)
            results = set(results) & set(old_results)
            if len(results) == 1:
                break
            if len(strings) == 0:
                break
        return results

        self.func_info[section] = list(results)

    def filter_by_sibling(self,section,config_section):
        siblings = eval(config_section["siblings"])
        for sibling in siblings:
            if sibling in self.func_info:
                if len(self.func_info[sibling]) == 1:
                    #One of the siblings is identified; We can identify the others based on this sibling
                    sibling_func = self.funcs[self.func_info[sibling][0]]
                    callers = sibling_func.callers 
                    candidate_callees = []
                    for caller in callers:
                        caller_func = self.funcs[caller]
                        callees = caller_func.callees
                        if len(candidate_callees) == 0:
                            candidate_callees = callees
                        else:
                            candidate_callees = list(set(candidate_callees) | set(callees))
                    for key in self.func_info:
                        if len(self.func_info[key]) == 1:
                            if self.func_info[key][0] in candidate_callees:
                                candidate_callees.remove(self.func_info[key][0])
                    if section not in self.func_info:
                        self.func_info[section] = candidate_callees
                    else:
                        self.func_info[section] = list(set(candidate_callees) & set(self.func_info[section]))

    def filter_by_callee(self,section,config_section):
        callees = eval(config_section["callee"])
        for callee in callees:
            if callee in self.func_info:
                if len(self.func_info[callee]) == 1:
                    callee_addr = self.func_info[callee][0]
                    callee_func = self.funcs[callee_addr]
                    candidates = callee_func.callers 
                    self.func_info[section] = candidates

    def filter_by_caller(self,section,config_section):
        callers = eval(config_section["caller"])
        for caller in callers:
            if caller in self.func_info:
                if len(self.func_info[caller]) == 1:
                    caller_addr = self.func_info[caller][0]
                    caller_func = self.funcs[caller_addr]
                    candidates = caller_func.callees 
                    self.func_info[section] = candidates




    def identify_funcs_with_configs(self,config_path):
        config = RawConfigParser()
        config.read(config_path)
        # We need to identify the address of warn_slowpath_null
        if "warn_slowpath_null" not in config.sections():
            print("error")
            #return 
        if "parameters" not in config["warn_slowpath_null"]:
            print("error")
            #return

        warn_slow_path_null_paras = eval(config["warn_slowpath_null"]["parameters"])
        self.identify_warn_null(warn_slow_path_null_paras)
        if self.warn_null == None:
            # Try to identify yhe warn null with partial emulation 
            self.enable_emu = True 
            print("Try to identify warn null via partial emulation")
            self.identify_warn_null(warn_slow_path_null_paras)
            if self.warn_null == None:
                print("we don't know the warn null")
            #return
        #print("warn null is 0x%x"%self.warn_null)


        # Init 
        # First Scanning
        for section in config.sections():
            if "strings" in config[section]:
                results = self.filter_by_strings(config[section])
                self.func_info[section] = list(results)
                print("section %s has the results %s"%(section,str(list(results))))
            if "possible_strings" in config[section]:
                strings = eval(config[section]["possible_strings"])
                results = self.identify_func_via_strings(strings[0])
                if len(results)>0:
                    self.func_info[section] = results
            elif "warn_slowpath_null" in config[section]:
                warn_parameter = eval(config[section]["warn_slowpath_null"])
                print("section:%s"%section)
                results = self.identify_func_via_warn_on(warn_parameter[0],warn_parameter[1])
                print(results)
                self.func_info[section] = results

        # Second Scanning
        while True:
            flag = False
            for section in config.sections():
                if section in self.func_info:
                    if len(self.func_info[section]) == 1:
                        continue
                if "callee" in config[section]:
                    self.filter_by_callee(section,config[section])
                if "caller" in config[section]:
                    callers = eval(config[section]["caller"])
                    for caller in callers:
                        if caller in self.func_info:
                            if len(self.func_info[caller]) == 1:
                                caller_addr = self.func_info[caller][0]
                                caller_func = self.funcs[caller_addr]
                                candidates = caller_func.callees 
                                self.func_info[section] = candidates
                                if len(candidates) == 1:
                                    flag = True
                                if "frequency_in_caller" in config[section]:
                                    candidates_details = caller_func.callee_details
                                    if int(config[section]["frequency_in_caller"]) == 0:
                                        self.func_info[section] = [max(set(candidates_details), key = candidates_details.count),]
                                        flag = True

                                #print("Extra Info: caller 0x%s"%callee)
                if "siblings" in config[section]:
                    self.filter_by_sibling(section,config[section])
                if section in self.func_info:
                    if len(self.func_info[section]) == 1:
                        True
            if flag == False:
                break

        while True:
            flag = False
            # Third Scanning
            for section in config.sections():
                if section not in self.func_info:
                    if "siblings" in config[section]:
                        self.filter_by_sibling(section,config[section])
                    if "callee" in config[section]:
                        self.filter_by_callee(section,config[section])
                    if "caller" in config[section]:
                        self.filter_by_caller(section,config[section])
                if section in self.func_info:
                    #if eval(config[section]["required"]) == False:
                    #    continue
                    if len(self.func_info[section]) == 1:
                        continue 
                    if "first_inst" in config[section]:
                        candidates = self.func_info[section]
                        if len(candidates) > 1:
                            print("first operand section %s "%section)
                            print(candidates)
                            new_candidates = []
                            first_inst = str(config[section]["first_inst"])
                            for candidate in candidates:
                                inst = self.insts[candidate]
                                if str(inst.mnemonic)+" "+str(inst.op_str) == str(first_inst).strip():
                                    new_candidates.append(candidate)
                            if len(new_candidates) >0:
                                self.func_info[section] = new_candidates

                    if "infinite_loop" in config[section]:
                        candidates = self.func_info[section]
                        if len(candidates) > 1:
                            loop_num = config[section]["infinite_loop"]
                            new_candidates = []
                            for candidate in candidates:
                                func = self.funcs[candidate]
                                func_loop_num = 0
                                for block_addr in func.blocks:
                                    block = self.blocks[block_addr]
                                    if block.infinite_loop():
                                        func_loop_num +=1
                                if func_loop_num == int(loop_num):
                                    new_candidates.append(candidate)
                            if len(new_candidates) >0:
                                self.func_info[section] = new_candidates
                                

                    if "orr" in config[section]:
                        candidates = self.func_info[section]
                        print(candidates)
                        if len(candidates) > 1:
                            orr_values = eval(config[section]["orr"])
                            new_candidates = []
                            for candidate in candidates:
                                tmp_flag = True
                                for orr_value in orr_values:
                                    if not self.logic_operation_value(candidate,ARM_INS_ORR,orr_value):
                                        tmp_flag = False 
                                if tmp_flag == True:
                                    new_candidates.append(candidate)
                            if len(new_candidates)>0:
                                self.func_info[section] = new_candidates
                        print(self.func_info[section])
                    if "return_value" in config[section]:
                        candidates = self.func_info[section]
                        if len(candidates) > 1:
                            return_value = int(config[section]["return_value"])
                            new_candidates = []
                            for candidate in candidates:
                                if self.has_specific_value(candidate,return_value):
                                    new_candidates.append(candidate)
                            if len(new_candidates) >0:
                                self.func_info[section] = new_candidates
                    if "no_return_value" in config[section]:
                        candidates = self.func_info[section]
                        if len(candidates) == 1:
                            continue 
                        no_return_value = int(config[section]["no_return_value"])
                        print("no return value %d"%no_return_value)
                        new_candidates = []
                        for candidate in candidates:
                            print("debug:",candidate)
                            if not self.has_specific_value(candidate,no_return_value):
                                print("no:",hex(candidate))
                                new_candidates.append(candidate)
                        if len(new_candidates) >0:
                            self.func_info[section] = new_candidates
                    if "no_str_offset" in config[section]:
                        candidates = self.func_info[section]
                        if len(candidates) == 1:
                            continue 
                        no_str_offsets = eval(config[section]["no_str_offset"])
                        new_candidates = []
                        for candidate in candidates:
                            flag = False
                            for no_str_offset in no_str_offsets:
                                if self.has_str_offset(candidate,no_str_offset):
                                    flag = True 
                            if flag == False:
                                new_candidates.append(candidate)
                        if len(new_candidates) >0:
                            self.func_info[section] = new_candidates
                    if "block_num" in config[section]:
                        candidates = self.func_info[section]
                        if len(candidates) > 1:
                            block_num = int(config[section]["block_num"]) 
                            new_candidates = []
                            for candidate in candidates:
                                if len(self.funcs[candidate].blocks) == block_num:
                                    new_candidates.append(candidate)
                            if len(new_candidates) >0:
                                self.func_info[section] = new_candidates
                    if "block_num_max" in config[section]:
                        candidates = self.func_info[section]
                        if len(candidates) > 1:
                            block_num_max = int(config[section]["block_num_max"]) 
                            new_candidates = []
                            for candidate in candidates:
                                if len(self.funcs[candidate].blocks) <= block_num_max:
                                    new_candidates.append(candidate)
                            if len(new_candidates) >0:
                                self.func_info[section] = new_candidates
                    if "callee_num" in config[section]:
                        callee_num = int(config[section]["callee_num"])
                        new_candidates = []
                        candidates = self.func_info[section]
                        if len(candidates) == 1:
                            continue
                        for candidate in candidates:
                            if len(self.funcs[candidate].callees) == callee_num:
                                new_candidates.append(candidate)
                        if len(new_candidates) >0:
                            self.func_info[section] = new_candidates
                        if len(new_candidates) > 1 and "callee_detail" in config[section]:
                            new_new_candidates = []
                            callee_details = eval(config[section]["callee_detail"])
                            for new_candidate in new_candidates:
                                function = self.funcs[new_candidate]
                                if len(function.callee_details) == len(callee_details):
                                    new_new_candidates.append(new_candidate)
                            if len(new_new_candidates) > 0:
                                self.func_info[section] = new_new_candidates 
                            if len(new_new_candidates) == 1:
                                continue

                        if len(new_candidates) > 1 and callee_num == 2:
                            new_new_candidates = []
                            if "callee" in config[section]:
                                callees = eval(config[section]["callee"])
                                identified_callee = None 
                                left_callee = None
                                for callee in callees:
                                    print("callee: %s"%callee)
                                    if self.is_identified(callee):
                                        identified_callee = callee
                                    else:
                                        left_callee = callee
                                if identified_callee == None or left_callee == None:
                                    print("Cannot be detected further")
                                    continue
                                if left_callee in config:
                                    if "callee_num" in config[left_callee]:
                                        callee_callee_num = int(config[left_callee]["callee_num"])
                                        for new_candidate in new_candidates:
                                            print("new_candidate:0x%x"%new_candidate)
                                            candidate_callees = self.funcs[new_candidate].callees.copy()
                                            print("identified_callee:%s"%identified_callee)
                                            identified_callee_addr = self.func_info[identified_callee][0]
                                            print("identified_calleee_addr: 0x%x"%identified_callee_addr)
                                            print("candidate_callees:")
                                            print(candidate_callees)
                                            candidate_callees.remove(identified_callee_addr)
                                            candidate_sibling = candidate_callees[0]
                                            if len(self.funcs[candidate_sibling].callees) == callee_callee_num:
                                                new_new_candidates.append(new_candidate)
                            print("new_new_candidates:")
                            print(new_new_candidates)
                            if len(new_new_candidates) > 0:
                                self.func_info[section] = new_new_candidates
                    if "nochange" in config[section]:
                        print("nochange in %s"%section)
                        if eval(config[section]["required"]) == False:
                            continue 
                        if section in self.func_info:
                            if len(self.func_info[section]) == 1:
                                continue 
                        if section not in self.func_info:
                            continue 

                        print("nochange in %s with candidates"%section)
                        candidates = self.func_info[section]
                        print(candidates)
                        nochange = eval(config[section]["nochange"])
                        new_candidates = []
                        for k in nochange:
                            if k not in self.func_info:
                                continue 
                            if len(self.func_info[k]) != 1:
                                continue 
                            callee_addr = self.func_info[k][0]
                            for candidate in candidates:
                                function = self.funcs[candidate]
                                for block_addr in function.blocks:
                                    block = self.blocks[block_addr]
                                    inst_addr = block.has_callee_at(callee_addr)
                                    print("inst addr: 0x%x"%inst_addr)
                                    if inst_addr != -1:
                                        insts = block.get_insts_before(inst_addr)
                                        for inst in insts:
                                            print("before is 0x%x"%inst.address)
                                        unchange_reg = nochange[k]
                                        print("uncahnge_reg: %d"%unchange_reg)
                                        if not self.change_reg(unchange_reg,insts):
                                            new_candidates.append(candidate)
                        if len(new_candidates) > 0:
                            self.func_info[section] = new_candidates;
                    if len(self.func_info[section]) == 1:
                        print("Identified new section:",section)

                        print(self.func_info[section])
                        flag = True
            if flag == False:
                break
    
        

        # Specific cases: Identify the set_handle_irq 
        # locate the _irq_handler and handle_arch_irq
        for section in config.sections():
            if section !="__of_find_node_by_path":
                continue
            if section not in self.func_info:
                continue 
            if len(self.func_info[section]) != 1:
                continue 
            func_addr = self.func_info[section][0]
            # might be inline 
            if self.is_recursive(func_addr):
                #inlined 
                print("is inlined")
                self.func_info["of_find_node_by_path"] = [func_addr,]
                continue
            else:
                print("is not inlined")
                #use caller to do filtering 
                callers = self.funcs[func_addr].callers 
                self.func_info["of_find_node_by_path"] = callers
                
  
        for section in config.sections():
            if section != "_irq_handler":
                continue 
            if "insts" not in config[section]:
                continue 
            handle_arch_irq = None
            possible_insts = eval(config[section]["insts"])
            candidates = []
            for block in self.blocks:
                for insts in possible_insts:
                    if self.blocks[block].include(insts):
                        inst =  self.blocks[block].insts[-4]
                        if inst.id != ARM_INS_LDR:
                            continue
                        if inst.operands[0].reg != ARM_REG_R1:
                            continue
                        handle_arch_irq_pointer = inst.address+ 2*4 + inst.operands[1].value.mem.disp 
                        handle_arch_irq = self.get_value_at_addr(handle_arch_irq_pointer)
                        print("handle_arch_irq: 0x%x"%handle_arch_irq)
            if handle_arch_irq == None:
                continue 
            #identify the set_handle_irq
            for func_addr in self.funcs:
                function = self.funcs[func_addr]
                if len(function.callees) > 0:
                    continue
                for block_addr in function.blocks:
                    if block_addr not in self.blocks:
                        continue
                    block = self.blocks[block_addr]
                    if handle_arch_irq in block.data_pointers:
                        candidates.append(func_addr) 
            self.func_info["set_handle_irq"] = candidates

        for section in config.sections():
            if section != "handle_level_irq":
                continue 
            if section not in self.func_info:
                continue 
            if len(self.func_info[section]) >= 4:
                # find the handle_level_irq from the 4 candidates
                tmp_results = {}
                candidates = self.func_info[section]
                print("handle_level_irq candidate:")
                for candidate in candidates:
                    print(hex(candidate))
                for candidate in candidates:
                    if len(self.funcs[candidate].blocks) in tmp_results:
                        tmp_results[len(self.funcs[candidate].blocks)+0.5] = candidate
                    else:
                        tmp_results[len(self.funcs[candidate].blocks)] = candidate
                print(tmp_results)
                key_lists = list(tmp_results.keys())
                key_lists.sort()
                print(key_lists)
                if "version" in config[section]:
                    if str(config[section]["version"]).startswith("2.6"):
                        self.func_info[section] = [tmp_results[key_lists[-2]],]
                else:
                    self.func_info[section] = [tmp_results[key_lists[-3]],]


 
        """
        for section in config.sections():
            if section != "pcpu_setup_first_chunk":
                continue 
            if section not in self.func_info:
                continue 
            if len(self.func_info[section])!= 1:
                continue 
            func_addr = self.func_info[section][0]
            print("pcpu setup first chunk is identified")

            percpu_string = eval(config[section]["strings"])[0]
            for block_addr in self.funcs[func_addr].blocks:
                block = self.blocks[block_addr]
                if self.has_string(block_addr,percpu_string):
                    print("address {} has percpu:cpu_possible_mask string".format(block_addr))
                    for inst in block.insts:
                        if inst.id == ARM_INS_LDR:
                            if len(inst.operands) == 2:
                                op1 = inst.operands[0]
                                if op1.reg == ARM_REG_R2: 
                                    op2 = inst.operands[1]
                                    if op2.type == ARM_OP_MEM:
                                        if op2.value.mem.base == ARM_REG_PC:
                                            pc_relative = inst.address+ 2*4 + op2.value.mem.disp
                                            data = self.get_value_at_addr(pc_relative)
                                            self.func_info["cpu_possible_mask"] = [data,]
                                            print("set the value of cpu_possible_mask {}".format(data))
                    print("Try for kernel 4.4.50")
                    if not self.insts[block_addr-0x4].group(ARM_GRP_JUMP):
                        print("It is not in group instructions")
                        set_r0 = False
                        print_func = None
                        # it means this block is jumped by somewhere else. Instructions before this block should be executed continuesly.
                        for inst in block.insts:
                            if inst.id == ARM_INS_LDR:
                                if len(inst.operands) == 2:
                                    op1 = inst.operands[0]
                                    if op1.reg == ARM_REG_R0: 
                                        op2 = inst.operands[1]
                                        if op2.type == ARM_OP_MEM:
                                            if op2.value.mem.base == ARM_REG_PC:
                                                pc_relative = inst.address+ 2*4 + op2.value.mem.disp
                                                if percpu_string  == self.get_string_at_addr(pc_relative,len(percpu_string)):
                                                    set_r0 == True
                            if set_r0 == True:
                                if inst.id == ARM_INS_BL:
                                    print_func = inst.address
                                    break

                        if print_func == None:
                            print_func = block.insts[-1].address
                        
                        print("printk function is 0x%x"%(print_func))
                        load_from = None
                        for i in range(20):
                            #go back to 20 instructions to locate the cpu possible mask
                            inst = self.insts[print_func -i*4 -4]
                            if inst.id == ARM_INS_LDR:
                                if len(inst.operands) == 2:
                                    if op2.type == ARM_OP_MEM:
                                        op1 = inst.operands[0]
                                        op2 = inst.operands[1]
                                        if op1.reg == ARM_REG_R2:
                                            if op2.reg == 11:
                                                # It is not register
                                                continue 
                                            load_from = op2.reg 
                                        if load_from != None:
                                            if op1.reg == load_from:
                                                if op2.value.mem.base == ARM_REG_PC:
                                                    pc_relative = inst.address+ 2*4 + op2.value.mem.disp
                                                    data = self.get_value_at_addr(pc_relative)
                                                    self.func_info["cpu_possible_mask"] = [data,]
                                                    print("set the value of cpu_possible_mask {}".format(data))
                                                    break
                                             

            if "version" in config[section]:
                version = config[section]["version"]
                if version == "3.18":
                    block = self.blocks[func_addr]
                    if len(block.data_pointers) == 0:
                        continue
                    cpu_possible_mask = block.data_pointers[0]
                    self.func_info["cpu_possible_mask"] = [cpu_possible_mask,]

        for section in config.sections():
            if section != "do_cpu_up":
                continue 
            if section not in self.func_info:
                continue 
            if len(self.func_info[section])!= 1:
                continue 
            if "cpu_possible_mask" in self.func_info:
                continue
            func_addr = self.func_info[section][0]
            
            block = self.blocks[func_addr]
            if len(block.data_pointers) == 0:
                continue 
            cpu_possible_mask = block.data_pointers[0]
            self.func_info["cpu_possible_mask"] = [cpu_possible_mask,]
            print("set the value of cpu_possible_mask in do cpu up")
        """
        # Check functions contain illegal instructions
        for section in config.sections():
            if section not in self.func_info:
                continue
            if len(self.func_info[section]) == 1:
                continue 
            if eval(config[section]["required"]) != True:
                continue
            print("try to detect the section %s"%section)
            for candidate in self.func_info[section]:
                print("section possible candidate is 0x%x"%candidate)
            possible_funcs = []
            funcs = self.func_info[section]
            for f in funcs:
                if self.is_illegal(f):
                    print("function 0x%x is illegal"%f)
                    continue
                else:
                    possible_funcs.append(f)
            if len(possible_funcs)>0:
                self.func_info[section] = possible_funcs

       
                
        results = {}
         
        for section in config.sections():
            if "required" not in config[section]:
                print("%s has no required attr"%section)
                continue
            required = eval(config[section]["required"])
            if required == True:
                if section not in self.func_info:
                    print("%s is not identified yet"%section)
                elif len(self.func_info[section]) != 1:
                    print("%s is not identified yet"%section)
                elif len(self.func_info[section]) == 1:
                    results[section] = self.func_info[section][0]
                    print("%s : 0x%x"%(section,self.func_info[section][0]))
        return results

        

if __name__ == "__main__":
    print("disasm the raw bytes")
    #d = Disasm("../images/openwrt_15_oxnas/oxnas_3_18_raw",0xc0008000)
    d = Disasm("../images/2_6_30_wrt350_kernel_raw",0xc0008000)
    print("There are %d functions"%len(d.funcs))
    #d = Disasm("../images/openwrt_15_bcm53xx/3_18_20_bcm53xx_raw",0xc0008000)
    #d = Disasm("../images/openwrt_15_realview/3_18_20_realview_raw",0xc0008000)
    #d = Disasm("../images/openwrt_15_imx6/3_18_20_imx6_raw",0x80008000)
    #d = Disasm("../images/openwrt_15_cns3xxx/3_18_20_cns3xxx_raw",0xc0008000)
    #d = Disasm("../images/openwrt_15_mvebu/3_18_20_mvebu_raw",0xc0008000)
    d.identify_funcs_with_configs("../configs/2.6.cfg")
