import contextlib
import datetime
import logging
import re
from typing import List
import urllib.parse

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion, format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins import timeliner
from volatility3.plugins.windows import info, pedump, pslist, psscan
from volatility3.plugins.windows import vadinfo

vollog = logging.getLogger(__name__)


class VolExoPass(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """ VolExoPass is a Volatility 3 plugin designed to extract potential Exodus Wallet passphrases from Windows memory dumps. """

    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
                return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
           requirements.VersionRequirement(
               name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
              ),
        ]


    def generate_timeline(self):
        for row in self._generator(
            pslist.PsList.list_processes(
                context=self.context, kernel_module_name=self.config["kernel"]
            )
        ):
            _depth, row_data = row
            if not isinstance(row_data[6], datetime.datetime):
                continue
            description = f"Test Load: Process {row_data[0]} {row_data[1]} Loaded {row_data[4]} ({row_data[5]}) Size {row_data[3]} Offset {row_data[2]}"
            yield (description, timeliner.TimeLinerType.CREATED, row_data[6])

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]
        
        procs = pslist.PsList.list_processes(
            context=self.context, kernel_module_name=self.config["kernel"], filter_func=filter_func
        )

        results = list(self._generator(procs=procs))
        
        try:
            print("\nExtracted Passphrases:\n")
            print("PID\tVAD\tAddress\tPassphrase")
            # print(results)
            for pid, vad_start, pass_addr, passphrase in results:
                print(f"{pid}\t{hex(vad_start)}\t{hex(pass_addr)}\t{passphrase}")
        except ValueError:
            pass
        return renderers.TreeGrid(
            [   
             ("COMPLETED", str)
            ],
            self._generator(procs=procs),
        )

    def _generator(self, procs):
        found_passes = set()
        results = []
        proc_count=0
        for proc in procs:
            proc_count += 1
            if proc_count == 1:
                print("\n\n Running VolExoPass Plugin....\n")
            process_name = proc.ImageFileName.cast(
                "string",
                max_length=proc.ImageFileName.vol.count,
                errors="replace",
            )
            if "exodus" in process_name.lower():
                # print("")
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                MAX_READ_SIZE = 0x6400000
                regex = re.compile(r'exodus\.wallet%22%2C%22passphrase%22%3A%22(.*?)%22%7D')
                count = 0
                # print(proc.UniqueProcessId)
                try:
                    for vad in proc.get_vad_root().traverse():
                        data_buffer = b""
                        start = vad.get_start()
                        size = vad.get_end() - start
                        size = min(vad.get_end() - start, MAX_READ_SIZE)
                        print(f"Reading {proc_id} VAD at {hex(start)} (Size: {hex(size)})")
                        try:
                            data_buffer += self.context.layers[proc_layer_name].read(start, size, pad=True)
                            match = regex.search(data_buffer.decode(errors="ignore"))
                            if match:
                                count=count+1
                                pass_addr = start + int(match.start())
                                decoded_pass = urllib.parse.unquote(match.group(1))
                                if decoded_pass not in found_passes:
                                    found_passes.add(decoded_pass)
                                results.append((int(proc_id), int(start), int(pass_addr), str(decoded_pass)))

                                # print(f"Found pass: {decoded_pass}")
                        except exceptions.InvalidAddressException:
                            continue                  
                except exceptions.InvalidAddressException:
                    continue
                if count == 0:
                    print(f"\n[-]No pass found in process {proc_id}\n")
                else:
                    print(f"\n[+]Found potential passphrase in process {proc_id}\n")
        for passwd in found_passes:
            # print(f"[+]Found pass: {passwd}") 
            pass
        return results

                    