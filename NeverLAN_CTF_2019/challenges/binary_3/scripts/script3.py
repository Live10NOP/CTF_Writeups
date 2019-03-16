import angr

def main():
	proj = angr.Project("../files/get_flag", auto_load_libs=False)
	cfg = proj.analyses.CFGFast(symbols=True)
	main_object = proj.loader.main_object


	roots = []
	# For every vertex in the control flow graph
	for node in cfg.graph.nodes:
		# If the vertex has no incoming edges (functions that are never called will satisfy this condition)
		if cfg.graph.in_degree(node) == 0:
			node_func = cfg.functions.function(addr=node.function_address)
			node_func_sec = main_object.find_section_containing(node_func.addr)
			if node_func_sec.name == '.text':
				roots.append(node_func)
	for root in roots:
		print(root)

if __name__ == "__main__":
	main()
