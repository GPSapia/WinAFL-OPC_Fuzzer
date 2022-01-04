import lief
from lief import PE

binary32 = PE.parse("uastack.dll")

patch_avoid_error = [0xEB]
patch_avoid_reset = [0xC3]

binary32.patch_address(0x100889D3, patch_avoid_error)           #avoid error, i'm not sure if it is needed
binary32.patch_address(0x10077460, patch_avoid_reset)

builder = lief.PE.Builder(binary32)

builder.build()

builder.write("patchedStack.dll")