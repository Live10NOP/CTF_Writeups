import angr
import claripy

def main():
    proj = angr.Project('a.out', auto_load_libs=False)

    start_state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(start_state)
    simgr.explore(find=0x40111d)
    assert len(simgr.found) > 0, "Could not find success state."
    found_state = simgr.found[0]

    symbolic_chars = [found_state.mem[found_state.regs.rbp + i].char.resolved for i in range(15)]
    for sym_char in symbolic_chars:
        found_state.add_constraints(sym_char != 0)
    symbolic_flag = claripy.Concat(*symbolic_chars)
    concrete_flag = found_state.solver.eval(symbolic_flag, cast_to=bytes)
    flag = concrete_flag.decode('ascii')
    assert flag == "CTF{S1MDf0rM3!}"
    print("{}".format(flag))


if __name__ == "__main__":
    main()
