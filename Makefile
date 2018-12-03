CFLAGS+=-I./src/ -g
COMPILE:=$(CC) $(CFLAGS)
all: randhash
amd64_Template.o: src/amd64/Template.s
	$(COMPILE) -c -o amd64_Template.o src/amd64/Template.s
amd64_Codegen.o: src/amd64/Codegen.c amd64_Template.o Codegen.o
	$(COMPILE) -c -o amd64_Codegen.o src/amd64/Codegen.c
Codegen.o: src/common/Codegen_generic.c
	$(COMPILE) -c -o Codegen.o src/common/Codegen_generic.c
chacha20.o: src/portable/chacha20/*
	$(COMPILE) -c -o chacha20.o src/portable/chacha20/chacha_merged.c
blake2.o: src/portable/blake2/*
	$(COMPILE) -c -o blake2.o src/portable/blake2/blake2b-ref.c
Hash.o: src/portable/Hash.c src/portable/Hash.h chacha20.o blake2.o
	$(COMPILE) -c -o Hash.o src/portable/Hash.c
Interpreter.o: src/portable/Interpreter.c src/portable/Interpreter.h
	$(COMPILE) -c -o Interpreter.o src/portable/Interpreter.c
randhash: src/randhash.c Interpreter.o Hash.o amd64_Codegen.o
	$(COMPILE) -o randhash ./*.o src/randhash.c