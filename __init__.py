from concurrent.futures import ThreadPoolExecutor, wait

from binaryninja.interaction import get_text_line_input
from binaryninja.function import Variable
from binaryninja.mediumlevelil import MediumLevelILInstruction
from binaryninja.enums import MediumLevelILOperation as mlilop
from binaryninja import (PluginCommand, BinaryView, Function, BackgroundTaskThread, Symbol,
                         log_info, log_warn, log_debug, log_error)


def iscall(i: MediumLevelILInstruction):
    return i.operation == mlilop.MLIL_CALL


def rename_caller(callee: Function, caller: Function, parami: int):
    i: MediumLevelILInstruction
    for i in filter(iscall, caller.mlil.instructions):
        if i.operands[1].constant == callee.start:
            i = i.operands[2][parami]
            if i.operation == mlilop.MLIL_CONST_PTR:
                name: str = caller.view.get_string_at(i.constant).value.split('(', 1)[0]
                caller.view.define_auto_symbol(Symbol(
                    caller.symbol.type,
                    caller.symbol.address,
                    short_name=name
                ))
                # just use the first one
                # a few wrong ones are fine imo
                break


class RenameTask(BackgroundTaskThread):
    def __init__(self, func: Function):
        super().__init__('renaming callers', True)
        self.func = func

    def run(self):
        param_str: str = get_text_line_input("enter name of parameter",
                                             "parameter name").decode('utf-8')
        try:
            param = next(p for p in self.func.parameter_vars if p.name == param_str)
            parami: int = self.func.parameter_vars.vars.index(param)
        except StopIteration:
            log_error(f'arg {param_str} not found')
            return

        # for commercial users
        with ThreadPoolExecutor(16) as t:
            log_info(f'processing {len(self.func.callers)} callers')
            # so i would filter for f.auto
            # but the flag is extremely unreliable
            for c in self.func.callers:
                t.submit(rename_caller, self.func, c, parami)

        log_info('renaming done')
    def cancel(self): pass
    def finish(self): pass


def rename(bv: BinaryView, func: Function):
    task = RenameTask(func)
    task.start()

PluginCommand.register_for_function(
    "rename callers to arg",
    "rename all callers of this function to the specified string argument",
    rename)
