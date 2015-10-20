'''
Created on 2014-12-2

@author: M.R. Farhadi
'''

import idaapi
import idautils
import idc
from sets import Set


def block_split(output_file, startEA, endEA):
    curName = GetFunctionName(startEA);
    dem = idc.Demangle(curName, idc.GetLongPrm(INF_SHORT_DN));
    if dem != None:
        curName = dem;
    
    first=startEA
    h = idautils.Heads(startEA, endEA)
    for i in h:
        mnem = idc.GetMnem(i)
        if mnem == "call" and i != endEA:
            first=idc.NextHead(i, endEA+1)
           
# end of block_split
#------------------------------------------------------------------------------------------------------------------------

def function_extract(output_file, func, cg_adjmat, funcs_id, callees, asm_filename):
    func_name = GetFunctionName(func)
    function_start_phrase = func_name + " proc near" 
    function_end_phrase = func_name + " endp" 

    print >> output_file, "+++++++++++++++++++++++++++++"
    print >> output_file, "Function Name: %s" % (func_name)
    print >> output_file, "     Function ID: %s" % (funcs_id[func_name])
    func_asm_start_address = get_line_number(function_start_phrase, asm_filename)
    func_asm_end_address = get_line_number(function_end_phrase, asm_filename)
    print >> output_file, "     ASM File Starting Address: %#s" % (func_asm_start_address)
    print >> output_file, "     ASM File Ending Address: %#s" % (func_asm_end_address)
    print >> output_file, "     Binary File Starting Address: %#x" % (func)
    print >> output_file, "     Binary File Ending Address: %#x" % (FindFuncEnd(func))
    print >> output_file, ""
    print >> output_file, "     Caller Functions:"
    
    for ref_ea in CodeRefsTo(func, 0):    
        caller_name = GetFunctionName(ref_ea)
        callees[caller_name] = callees.get(caller_name, Set()) #add the functions from "CodesRefsTo" to a dictionary for extracting CG and CG adjacency Matrix
        callees[caller_name].add(func_name)  
        print >> output_file, "		%s" % (caller_name)
    
# end of function_extract
#------------------------------------------------------------------------------------------------------------------------

def cg_extract(output_file, cg_adjmat, funcs_id, callees, func_num):
    functions = callees.keys()
    
    for key in functions:
        cg_row =[0]*func_num
        print >> output_file, "key: %s " % (key) 
        if callees.has_key(key):
            for calling in callees[key]:
                cg_row[funcs_id[calling]] = 1
        print >> output_file, "key: %s " % (key) 
        print >> output_file,"cg_row: ", cg_row
        if key in funcs_id:
            cg_adjmat[funcs_id[key]].append(cg_row)            
                                                          
    print >> output_file, "CG Adjacency Matrix:\n"
    cnt = 0
    for cg_row in cg_adjmat:
        print >> output_file, "Function ID [%d]: " %(cnt) , cg_row
        cnt += 1

# end of cg_extract
#------------------------------------------------------------------------------------------------------------------------

def BB_extract(output_file, func, asmplus_filename):
    cnt = 0
    f = idaapi.FlowChart(idaapi.get_func(func))
    cfg_adjmat = []
    
    for block in f:
        cfg_row =[0]*f.size
        print >> output_file, ""
        print >> output_file, "	Basic Block:"
        block_split(output_file, block.startEA, block.endEA)
        print >> output_file, "		BB_ID: [%d]" % (block.id)
        
        bb_asm_start_address = "{0:x}".format(block.startEA)
        bb_asm_end_address = "{0:x}".format(block.endEA)        
        
        print >> output_file, "		ASM File Starting Address: %#s" % (get_line_number(bb_asm_start_address.upper(), asmplus_filename))
        print >> output_file, "		ASM File Ending Address: %#s" % (get_line_number(bb_asm_end_address.upper(), asmplus_filename) - 1 )
        
        print >> output_file, "		Binary File Starting Address: %#x" % (block.startEA)
        print >> output_file, "		Binary File Ending Address: %#x" % (block.endEA)
        
        print >> output_file, "		Basic Block Successors:"
        
        for succ_block in block.succs():
            cfg_row[succ_block.id] = 1
            print >> output_file, "			Starting Address: %x - Ending Address: %x - BB_ID: [%d]" % (succ_block.startEA, succ_block.endEA, succ_block.id)
        #print >> output_file, "Basic Block predecessors:"
        #for pred_block in block.preds():
        #   print >> output_file, "Starting Address: %x - Ending Address: %x BB_ID:[%d]:" % (pred_block.startEA, pred_block.endEA, pred_block.id)
        cfg_adjmat.append(cfg_row)
        print >> output_file, "-----------------------------"	
            
    print >> output_file, "CFG Adjacency Matrix for Function: %s\n" % (GetFunctionName(func))
    for cfg_row in cfg_adjmat:
        print >> output_file, "BB_ID [%d]: " %(cnt), cfg_row
        cnt += 1
        print >> output_file, "\n"
        
# end of BB_extract
#------------------------------------------------------------------------------------------------------------------------

def get_line_number(phrase, file_name):
    with open(file_name) as f:
        for i, line in enumerate(f, 1):
            if phrase in line:
                return i
                
# end of get_line_number
#------------------------------------------------------------------------------------------------------------------------
                
def controller():
    funcs_id = dict()  # to store functions and their IDs 
    callees = dict()
    func_num = 0
    func_id = 0
    cg_adjmat = []
    info_filename = idc.AskFile(1, "*.*", "Extract Binary File Info")

    basename = idc.GetInputFile()
    info_filename = basename + ".info"    
    asm_filename = basename + ".asm"  
    asmplus_filename = basename + ".asmplus"    
    idc.GenerateFile(idc.OFILE_ASM, basename + ".asm", 0, idc.BADADDR, 0)
    idc.GenerateFile(idc.OFILE_LST, basename + ".asmplus", 0, idc.BADADDR, 0)
         
    output_file = open(info_filename,'w')        
    asm_file = open(asm_filename,'r')
    asmplus_file = open(asm_filename,'r')
    
    funcs = idautils.Functions()
    funcs_iterator = idautils.Functions()
    
    # scan all functions to extract number of functions and add them to the funcs_id
    for i in funcs_iterator:
        func_name = GetFunctionName(i)
        funcs_id.update({func_name:func_id})
        func_num += 1
        func_id += 1
        cg_adjmat.append([])
        
    for f in funcs:        
        func_name = GetFunctionName(f)              
        function_extract(output_file, f, cg_adjmat, funcs_id, callees, asm_filename) # extract functions data
        BB_extract(output_file, f, asmplus_filename) # extract basic blocks data, CFG and CFG adjacency matrices                                

    cg_extract(output_file, cg_adjmat, funcs_id, callees, func_num) # extract CG and CG adjacency matrix

        
# end of controller
#------------------------------------------------------------------------------------------------------------------------      

q = None
f = None
idc.Wait()
controller()

