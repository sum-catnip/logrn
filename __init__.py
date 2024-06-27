from concurrent.futures import ThreadPoolExecutor, wait

from binaryninja import (BackgroundTaskThread, BinaryView, Function,
                         PluginCommand, Symbol, log_info)
from binaryninja.enums import MediumLevelILOperation as mlilop
from binaryninja.function import Variable
from binaryninja.interaction import get_choice_input
from binaryninja.mediumlevelil import MediumLevelILInstruction


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
        choices = [n.name for n in self.func.type.parameters]
        param_idx: int|None = get_choice_input("Select parameter to use as name", "logrn", choices)
        if param_idx is None:
            return

        # for commercial users
        with ThreadPoolExecutor(16) as t:
            log_info(f'processing {len(self.func.callers)} callers')
            # filter for funcs that have not been renamed
            for c in self.func.callers:
                if c.symbol.auto:
                    t.submit(rename_caller, self.func, c, param_idx)

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
