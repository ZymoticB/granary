"""Generate the macros mapping kernel functions to their addresses
memory.

Author:       Peter Goodman (peter.goodman@gmail.com)
Copyright:    Copyright 2012-2013 Peter Goodman, all rights reserved.
"""

import sys

SYMBOLS = set()
FOUND_SYMBOLS = {}
ADDRESSES = []
SYMBOL_TO_ADDRESS_INDEX = {}

if "__main__" == __name__:
  prefix = "#ifndef CAN_WRAP_"
  prefix_len = len(prefix)
  lines = []

  with open(sys.argv[1], "r") as lines_:
    for line in lines_:
      lines.append(line)
      line = line.strip(" \r\n\t")
      if line.startswith(prefix):
        SYMBOLS.add(line[prefix_len:])
  
  # special function that we need!
  SYMBOLS.add("module_alloc_update_bounds")
  SYMBOLS.add("process_one_work")

  with open("kernel.syms", "r") as lines_:
    for line in lines_:
      line = line.strip(" \r\n\t")
      line = line.replace("\t", " ")
      parts = line.split(" ")
      sym = parts[2]
      
      ADDRESSES.append(int(parts[0], base=16))

      if sym in SYMBOLS:
        FOUND_SYMBOLS[sym] = parts[0]
        SYMBOL_TO_ADDRESS_INDEX[sym] = len(ADDRESSES) - 1

  with open(sys.argv[1], "w") as f:
    new_lines = []
    for sym, addr in FOUND_SYMBOLS.items():
      func_index = SYMBOL_TO_ADDRESS_INDEX[sym]
      func_len = ADDRESSES[func_index + 1] - ADDRESSES[func_index]

      new_lines.append("#ifndef DETACH_ADDR_%s\n" % sym)
      new_lines.append("#    define DETACH_ADDR_%s 0x%s\n" % (sym, addr))
      new_lines.append("#    define DETACH_LENGTH_%s %d\n" % (sym, func_len))
      new_lines.append("#endif\n")
    
    missing = SYMBOLS - set(FOUND_SYMBOLS.keys())
    
    if "module_alloc_update_bounds" in missing:
      missing.remove("module_alloc_update_bounds")

    for sym in missing:
      new_lines.append("#ifndef CAN_WRAP_%s\n" % sym)
      new_lines.append("#    define CAN_WRAP_%s 0\n" % sym)
      new_lines.append("#endif\n")
    
    new_lines.extend(lines)
    f.write("".join(new_lines))

