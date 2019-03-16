import angr

def main():
	proj = angr.Project("../files/get_flag", auto_load_libs=False)
	cfg = proj.analyses.CFGFast(symbols=True)
	
	# Call our functions, when these symbols are encountered
	proj.hook_symbol('gethostbyname', GetHostByNameSimProc())
	proj.hook_symbol('printf', PrintfSimProc())

	# Create a state starting at the function 'd'
	d_func = cfg.functions.function(name='d')
	call_state = proj.factory.call_state(addr=d_func.addr)
	call_state.regs.rbp = 0

	# Simulate calling function 'd'
	simgr = proj.factory.simulation_manager(call_state)
	simgr.run()


class GetHostByNameSimProc(angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']):
	def run(self, arg_name_addr_bv, *args):
		# dereference the argument pointing to the host name string
		arg_name_addr = self.state.solver.eval(arg_name_addr_bv.to_claripy())
		arg_name = self.state.mem[arg_name_addr].string.concrete
		print("gethostbyname called with arg: {}".format(arg_name))

		return super(GetHostByNameSimProc, self).run(self, arg_name_addr_bv, args)

class PrintfSimProc(angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']):
	def run(self, arg_fmt_addr_bv, arg_str_addr_bv):
		# dereference the argument pointing to the string to print
		arg_str_addr = self.state.solver.eval(arg_str_addr_bv.to_claripy())
		arg_str = self.state.mem[arg_str_addr].string.concrete
		print("printf called with arg: {}".format(arg_str))

		return super(PrintfSimProc, self).run(self, arg_fmt_addr_bv, arg_str_addr_bv)


if __name__ == "__main__":
	main()
