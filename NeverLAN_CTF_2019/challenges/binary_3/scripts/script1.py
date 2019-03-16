import angr

def main():
	proj = angr.Project("../files/get_flag", auto_load_libs=False)

	main_object = proj.loader.main_object
	text_section = main_object.find_section_containing(main_object.entry)
	assert text_section.name == '.text'
	text_sec_min_addr, text_sec_max_addr = (text_section.min_addr, text_section.max_addr)

	# Create a control flow graph of the .text section using the symbols as starting point to search for functions
	cfg = proj.analyses.CFGFast(symbols=True, regions=[(text_sec_min_addr, text_sec_max_addr)])

	# Print the discovered functions
	for func_addr in cfg.functions:
		func = cfg.functions[func_addr]
		func_name = func.name
		print("{name} @ (0x{addr:x})".format(name=func_name, addr=func_addr))

if __name__ == "__main__":
	main()
