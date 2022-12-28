#!/usr/bin/env python3

import atheris
import sys

import fuzz_helpers

with atheris.instrument_imports():
    import rarfile



def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True) as rar:
            rf = rarfile.RarFile(rar)
            for _ in rf.infolist():
                pass
    except (rarfile.Error):
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
