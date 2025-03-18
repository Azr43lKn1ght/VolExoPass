

## VolExoPass - Exodus Wallet Passphrase Extraction Plugin

VolExoPass is a Volatility 3 plugin designed to extract potential Exodus Wallet passphrases from Windows memory dumps. The plugin scans process virtual address space (VAD) for passphrase patterns associated with Exodus Wallet and extracts them for analysis. The plugin also pinpoints the VAD allocation address, the address of the passphrase and the process ID (PID) associated with the passphrase.

### Plugin Usage

To use the plugin, simply place it in the volatility3/framework/plugins/windows subfolder.

```bash
python vol.py -f <memory_dump> windows.VolExoPass
```

### Plugin Output

The plugin extracts potential Exodus Wallet passphrases and prints them to the console.

``` shell
python .\vol.py -f ..\..\Gotham_Underground\chall\Exodus.raw  windows.VolExoPass
Volatility 3 Framework 2.24.0
Progress:  100.00               PDB scanning finished

 Running VolExoPass Plugin....

Reading 2352 VAD at 0x7ffb45070000 (Size: 0x1e3fff)
Reading 2352 VAD at 0x1bdd4b40000 (Size: 0x1ffff)
Reading 2352 VAD at 0x1bd91840000 (Size: 0xa38fff)
Reading 2352 VAD at 0x1bd8f940000 (Size: 0xffff)
Reading 2352 VAD at 0xaa40e00000 (Size: 0x7fffff)
Reading 2352 VAD at 0xaa3ce00000 (Size: 0x7fffff)

---------------[snip]---------------
Extracted Passphrases:

PID     VAD     Address Passphrase
2352    0x1bdd5d10000   0x1bdd5d2bae1   yb#uO7&n%$£6[E310
2352    0x1bdd5d60000   0x1bdd5d7bd0e   yb#uO7&n%$£6[E310
2352    0x1c600000000   0x1c60073ef8f   yb#uO7&n%$£6[E310
2352    0x614bffff0000  0x614c018ee72d  yb#uO7&n%$£6[E310
5616    0xd5bffff0000   0xd5c0034b4b5   yb#uO7&n%$£[E310
6700    0x292400000000  0x29240272ed2c  yb#uO7&n%$£6[E310
6700    0x3b600000000   0x3b601281fd6   yb#uO7&n%$£6[E310
3028    0x2d200000000   0x2d2013312ec   yb#uO7&n%$£6[E310
3028    0x356000000000  0x3560022f9cfb  yb#uO7&n%$£6[E310
7828    0x1ba00000000   0x1ba006e8a55   yb#uO7&n%$£6[E310
7828    0x161400000000  0x16140296fb8b  yb#uO7&n%$£6[E310
5848    0x141c5c80000   0x141c5c9bae1   yb#uO7&n%$£6[E310
5848    0x2e6800000000  0x2e68002ab9f4  yb#uO7&n%$£6[E310
3960    0xf800000000    0xf800657d91    yb#uO7&n%$£6[E310
3960    0x2477cf90000   0x2477cfabd0e   yb#uO7&n%$£6[E310
```

![alt text](Exodus.png)

### Troubleshooting

If you encounter errors related to Volatility 3 requirements, ensure your Python environment has all dependencies installed.

### Author

**Azr43lKn1ght -** [X](https://X.com/Azr43lKn1ght) | [Linkedin](https://www.linkedin.com/in/NithinChenthurPrabhu) | [Github](https://github.com/Azr43lKn1ght)

### License
This plugin is released under the MIT License. See LICENSE for details.