import angr

def main():
	proj = angr.Project("../files/get_flag", auto_load_libs=False)
	cfg = proj.analyses.CFGFast(symbols=True)
	main_object = proj.loader.main_object


	# Starting at the function 'd' do a DFS on the called functions
	d_func = cfg.functions.function(name='d')
	stack = [d_func]
	visited = set()
	while len(stack) > 0:
		func = stack.pop()
		func_name = func.name
		func_addr = func.addr
		print("{name} @ (0x{addr:x}) ->".format(name=func_name, addr=func_addr))
		# For every function called from the currently visited function
		call_sites = func.get_call_sites()
		for call_site in call_sites:
			target_func_addr = func.get_call_target(call_site)
			target_func = cfg.functions.function(addr=target_func_addr)
			target_func_sec = main_object.find_section_containing(target_func.addr)
			target_func_name = target_func.name
			print("\t{name} @ (0x{addr:x})".format(name=target_func_name, addr=target_func_addr))
			# If we have not yet visited the called function and it is not a library function (it is in the .text section)
			if (not target_func in visited) and target_func_sec.name == '.text':
				# Add the function to be visited
				visited.add(target_func)
				stack.append(target_func)

if __name__ == "__main__":
	main()
