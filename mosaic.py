# Memory Mosaic
# Logan Nommensen
# Grand Valley State University
# CIS 430
# 11/282023

from volatility3.framework import renderers, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.windows import pslist
from volatility3.framework.renderers import format_hints


class Mosaic(interfaces.plugins.PluginInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                               architectures=["Intel32", "Intel64"]),
                requirements.ListRequirement(name='pid',
                                             element_type=int,
                                             description="Process IDs to include (all other processes are excluded)",
                                             optional=True),
                requirements.PluginRequirement(name='pslist',
                                               plugin=pslist.PsList,
                                               version=(2, 0, 0))]

    def _generator(self, procs):

        for proc in procs:

            for entry in proc.load_order_modules():

                BaseDllName = FullDllName = renderers.UnreadableValue()
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                    # We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
                    FullDllName = entry.FullDllName.get_string()
                except exceptions.InvalidAddressException:
                    pass

                yield (0, (proc.UniqueProcessId,
                           proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count,
                                                   errors='replace'),
                           format_hints.Hex(entry.DllBase), format_hints.Hex(entry.SizeOfImage),
                           BaseDllName, FullDllName))

    def run(self):

        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        kernel = self.context.modules[self.config['kernel']]

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Base", format_hints.Hex),
                                   ("Size", format_hints.Hex),
                                   ("Name", str),
                                   ("Path", str)],
                                  self._generator(pslist.PsList.list_processes(self.context,
                                                                               kernel.layer_name,
                                                                               kernel.symbol_table_name,
                                                                               filter_func=filter_func)))
