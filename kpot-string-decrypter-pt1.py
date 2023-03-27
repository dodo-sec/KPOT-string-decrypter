import ida_bytes
import idautils
import idc

def search_offset(x):
    #get offset of string table that's moved into eax
    if idc.print_insn_mnem(prev_head(x)) == 'mov' and idc.print_operand(prev_head(x), 0) == 'eax':
        return ida_bytes.get_byte(prev_head(x)+1)
    #check if previous instruction is 'pop eax' while ignoring offsets that lead to non-string values
    elif ida_bytes.get_byte(prev_head(x)) == 0x58 and ida_bytes.get_byte(prev_head(prev_head(prev_head(x)))+1) != 0x4c and ida_bytes.get_byte(prev_head(prev_head(prev_head(x)))+1) != 0x43 and ida_bytes.get_byte(prev_head(prev_head(prev_head(x)))+1) != 0x44:  #check if previous instruction is 'pop eax'
        #get offset that is pushed to the stack
        return ida_bytes.get_byte(prev_head(prev_head(prev_head(x)))+1)
    return 0   
    
def get_str_entry(eax_offset):
    string_entry = (eax_offset * 8) + 0x401288
    return(string_entry)
        
def decrypt_str(entry):
    xor_key = ida_bytes.get_byte(entry)
    str_size = ida_bytes.get_byte(entry + 2)
    counter = 0
    newarray = bytearray()
    while counter < str_size:
        encryp_str = ida_bytes.get_byte(ida_bytes.get_dword(entry+4)+counter)
        newarray.append(encryp_str ^ xor_key)
        counter += 1
    return(newarray.decode('UTF-8'))

#use address of corresponding decryption sub in your sample
xrefs = set(idautils.CodeRefsTo(0x0040C8F5,0))

for xref in xrefs:
    offset = search_offset(xref)
    if offset > 0:
        str_entry = get_str_entry(offset)
        comm_str = decrypt_str(str_entry)
        print('Setting decrypted string ', comm_str,  'as comment at: ', hex(prev_head(prev_head(xref))))
        #set decrypted string as comment next to the var that will receive it
        ida_bytes.set_cmt(prev_head(prev_head(xref)), comm_str, 0)
    else:
        print('Could not decrypt xref:', hex(xref))
