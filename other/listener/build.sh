#!/bin/bash

pyinstaller --onefile --hidden-import=_cffi_backend  listener.py 

staticx ./dist/listener ./listener.bin
